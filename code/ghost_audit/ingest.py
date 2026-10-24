"""Participant evidence adapters. No answer files are opened by this module."""
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
from collections import defaultdict
from pathlib import Path

from .identity import normalize
from .models import Observation, timestamp

COLLECTIONS = {
    'customer_profiles':('account_service','USER_PROFILE'),
    'profile_lookups':('account_service','USER_PROFILE'),
    'account_tombstones':('account_service','ACCOUNT_TOMBSTONE'),
    'customer_account_tombstones':('account_service','ACCOUNT_TOMBSTONE'),
    'customer_search_documents':('search_service','SEARCH_INDEX_ENTRY'),
    'search_documents_primary':('search_service','SEARCH_INDEX_ENTRY'),
    'index_queries':('search_service','SEARCH_INDEX_ENTRY'),
    'customer_analytics_profiles':('analytics_platform','ANALYTICS_PROFILE'),
    'customer_analytics_reports':('analytics_platform','ANALYTICS_PROFILE'),
    'analytics_profiles':('analytics_platform','ANALYTICS_PROFILE'),
    'support_records':('support_platform','SUPPORT_MESSAGE'),
    'support_messages':('support_platform','SUPPORT_MESSAGE'),
    'support_conversations':('support_platform','SUPPORT_MESSAGE'),
    'ticket_attachments':('support_platform','SUPPORT_ATTACHMENT'),
    'deleted_customer_references':('identity_service','ACCOUNT_TOMBSTONE'),
    'retained_order_records':('order_service','LEGAL_HOLD_RECORD'),
    'security_audit_events':('security_service','SECURITY_AUDIT_LOG'),
    'backup_catalog':('backup_service','BACKUP_ARCHIVE'),
    'support_attachments':('support_platform','SUPPORT_ATTACHMENT'),
    'tickets':('support_platform','SUPPORT_MESSAGE'),
    'customer_exports':('export_service','USER_EXPORT'),
    'export_jobs':('export_service','USER_EXPORT'),
    'customer_export_jobs':('export_service','USER_EXPORT'),
    'exports':('export_service','USER_EXPORT'),
    'connector_subscriptions':('integration_service','DATA_FLOW'),
    'connectors':('integration_service','DATA_FLOW'),
    'connector_configurations':('integration_service','DATA_FLOW'),
    'backup_restore_entries':('backup_service','BACKUP_ARCHIVE'),
    'restore_entries':('backup_service','BACKUP_ARCHIVE'),
    'backup_archives':('backup_service','BACKUP_ARCHIVE'),
    'security_audit_records':('security_service','SECURITY_AUDIT_LOG'),
    'audit_records':('security_service','SECURITY_AUDIT_LOG'),
    'legal_orders':('order_service','LEGAL_HOLD_RECORD'),
    'legal_hold_records':('order_service','LEGAL_HOLD_RECORD'),
}
SYSTEM_CATEGORY={'account_service':'USER_PROFILE','profile_service':'SECONDARY_IDENTIFIER','search_service':'SEARCH_INDEX_ENTRY','analytics_platform':'ANALYTICS_PROFILE','support_platform':'SUPPORT_MESSAGE','integration_service':'DATA_FLOW','backup_service':'BACKUP_ARCHIVE','security_service':'SECURITY_AUDIT_LOG','export_service':'USER_EXPORT','marketing_service':'MARKETING_PROFILE','notification_service':'EMAIL_DELIVERY_LOG','cache_service':'CACHE_ENTRY'}
SYSTEM_CATEGORY.update({'support_replica':'SECONDARY_IDENTIFIER','marketing_platform':'MARKETING_PROFILE','identity_service':'ACCOUNT_TOMBSTONE','object_storage':'SUPPORT_ATTACHMENT','email_service':'EMAIL_DELIVERY_LOG'})
IDENTITY_FIELDS={'user_id','customer_reference','subject_reference','subject_ref','subject_key','lookup_key','lookup_value','match_key','owner_key','correlation_key','scan_key','email','email_hash','phone','owner_email','owner_phone','requester_email','requester_phone','customer_email','uploaded_by','subject_selector'}
IDENTITY_FIELDS.add('matched_value')
IDENTITY_FIELDS.add('query')
NULLS={'null','none','[redacted]','redacted','anonymous','anonymized','no direct identifier',''}
ISO=r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z'


def read_csv(path):
    if not Path(path).exists(): return []
    with open(path,newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))


def flatten(data):
    result={}
    for k,v in data.items():
        if isinstance(v,dict):result.update(flatten(v))
        else:result[k]=v
    return result


def keys_from(data):
    result=set()
    for k,v in flatten(data).items():
        if k in IDENTITY_FIELDS and v is not None:
            key=normalize(v)
            if key not in NULLS:result.add(key)
    return result


def truth(value):
    if value is True or str(value).lower() in {'1','true','yes','allow','allowed','enabled'}:return True
    if value is False or str(value).lower() in {'0','false','no','deny','denied','disabled','blocked'}:return False
    return None


def infer_category(system,collection,record):
    if record.get('record_type'):return record['record_type']
    if collection in COLLECTIONS:return COLLECTIONS[collection][1]
    if 'tombstone' in collection or str(record.get('account_status','')).upper()=='DELETED_TOMBSTONE':return 'ACCOUNT_TOMBSTONE'
    if 'attachment' in collection:return 'SUPPORT_ATTACHMENT'
    if 'restore_allowed' in record:return 'BACKUP_ARCHIVE'
    if 'enabled' in record and 'connector_name' in record:return 'DATA_FLOW'
    if 'retention_until' in record and system=='security_service':return 'SECURITY_AUDIT_LOG'
    if 'retention_reason' in record:return 'LEGAL_HOLD_RECORD'
    if 'owner_email' in record and ('file_name' in record or 'object_key' in record):return 'USER_EXPORT'
    if system=='analytics_platform' or 'analytics' in collection:return 'ANALYTICS_PROFILE'
    return SYSTEM_CATEGORY.get(system,'')


def infer_state(category,fields):
    result=str(fields.get('result','')).upper()
    explicit={'FOUND':'PRESENT','NOT_FOUND':'ABSENT','IDENTIFIABLE':'PRESENT','ANONYMIZED':'ANONYMIZED','REDACTED':'REDACTED','ACTIVE':'ACTIVE','DISABLED':'DISABLED','BLOCKED':'BLOCKED'}
    if category=='ACCOUNT_TOMBSTONE':
        direct={'name','full_name','display_name','email','phone','email_hash','requester_name','requester_email','requester_phone','customer_email','owner_email','owner_phone','address','postal_address','ip_address'}
        if any(k in fields and normalize(fields[k]) not in NULLS for k in direct):return 'PRESENT'
        stable=next((fields[k] for k in ('user_id','subject_reference','customer_reference') if normalize(fields.get(k)) not in NULLS),None)
        covered={'name','email','phone','email_hash'}.issubset(fields)
        internal=stable and '@' not in str(stable) and not re.fullmatch(r'[+\d ()-]{7,}',str(stable))
        return 'REDACTED' if internal and covered else ''
    if fields.get('record_type') and result in explicit:return explicit[result]
    if category=='DATA_FLOW':
        flag=truth(fields.get('enabled',fields.get('scheduler_registered')))
        return 'ACTIVE' if flag is True else 'DISABLED' if flag is False else ''
    if category=='BACKUP_ARCHIVE':
        flag=truth(fields.get('restore_allowed',fields.get('restore_decision',fields.get('decision'))))
        return 'ACTIVE' if flag is True else 'BLOCKED' if flag is False else ''
    if fields.get('status_code',fields.get('http_status')) in (404,'404') or str(fields.get('rows',''))=='0':return 'ABSENT'
    if category=='SEARCH_INDEX_ENTRY':
        hits=fields.get('hits',{})
        total=hits.get('total') if isinstance(hits,dict) else None
        if total is None:total=fields.get('total_hits')
        if str(total)=='0' or result=='MISS':return 'ABSENT'
    if category in {'ANALYTICS_PROFILE','PRODUCT_TELEMETRY'}:
        attrs={'email','email_hash','phone','customer_reference','user_id','subject_reference'}
        if any(k in fields and normalize(fields[k]) not in NULLS for k in attrs):return 'PRESENT'
        if str(fields.get('direct_identifiers',''))=='0' or sum(k in fields for k in attrs)>=3:return 'ANONYMIZED'
        if str(fields.get('direct_identifiers','')) not in {'','0'}:return 'PRESENT'
        return ''
    if category in {'SUPPORT_MESSAGE','ACCOUNT_TOMBSTONE','EMAIL_DELIVERY_LOG'}:
        if fields.get('detector')=='direct_identifier' and normalize(fields.get('matched_value')) not in NULLS:return 'PRESENT'
        attrs={'name','full_name','display_name','email','phone','email_hash','requester_name','requester_email','requester_phone','customer_email'}
        if any(k in fields and normalize(fields[k]) not in NULLS for k in attrs):return 'PRESENT'
        for k in ('message_text','message_excerpt','body','text'):
            if re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\+\d[\d ()-]{6,}',str(fields.get(k,''))):return 'PRESENT'
        if any(str(fields.get(k,'')).strip().casefold()=='[redacted]' for k in ('message_text','message_excerpt','body','text')):return 'REDACTED'
        if str(fields.get('direct_identifiers',fields.get('pii_matches','')))=='0' or sum(k in fields for k in attrs)>=3:return 'REDACTED'
        return ''
    return 'PRESENT'


class Store:
    def __init__(self,dataset_path):
        self.root=Path(dataset_path)
        self.identities=read_csv(self.root/'user_identities.csv');self.history=read_csv(self.root/'user_audit_log.csv')
        self.activities=read_csv(self.root/'system_activity.csv');self.rules=read_csv(self.root/'deletion_rules.csv')
        self.manifest=read_csv(self.root/'evidence_files.csv')
        self.observations=[];self.scopes=[];self.documents=[];self.issues=[];self.files={};self.resource_links=[]
        self.evidence_times={r['file_id']:r['captured_at'] for r in self.manifest}
        self.evidence_times.update({r['activity_id']:r['event_time'] for r in self.activities})
        self.evidence_times.update({r['audit_id']:r['event_time'] for r in self.history})
        for entry in self.manifest:
            self._load(entry)
        self._activities()
        self.by_resource=defaultdict(list);self.by_identity=defaultdict(list)
        for o in self.observations:
            self.by_resource[o.resource_id].append(o)
            for k in o.identity_keys:self.by_identity[k].append(o)

    def add(self,entry,record,system='',collection='',at='',scope='logical',locator='',state=None):
        fields=flatten(record);system=record.get('system',record.get('origin_system',system))
        if collection in COLLECTIONS and system not in SYSTEM_CATEGORY and not record.get('system') and not record.get('origin_system'):system=COLLECTIONS[collection][0]
        category=infer_category(system,collection,fields)
        resource=record.get('resource_id',record.get('id',''))
        if not resource or not system or not category:return
        at=record.get('observed_at',record.get('recorded_at',at or record.get('updated_at',record.get('indexed_at',entry['captured_at']))))
        state=state if state is not None else infer_state(category,fields)
        o=Observation(entry['file_id'],system,str(resource),category,state,at,entry['captured_at'],fields,keys_from(record),scope,locator)
        self.observations.append(o)
        for key in ('source_resource_id','parent_resource_id'):
            if record.get(key):self.resource_links.append((str(resource),record[key],entry['captured_at'],at))
        return o

    def _load(self,entry):
        path=(self.root/entry['file_path']).resolve()
        if not path.is_relative_to(self.root.resolve()):raise ValueError('Manifest path escapes dataset')
        try:
            raw=path.read_bytes();self.files[entry['file_id']]={'path':entry['file_path'],'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
            ext=path.suffix.lower()
            if ext=='.json':self._json(entry,json.loads(raw.decode('utf-8-sig')))
            elif ext=='.sql':self._sql(entry,raw.decode('utf-8-sig'))
            elif ext=='.log':self._log(entry,raw.decode('utf-8-sig'))
            elif ext=='.txt':self._text(entry,raw.decode('utf-8-sig'))
            elif ext=='.pdf':
                from pypdf import PdfReader
                text='\n'.join(p.extract_text() or '' for p in PdfReader(path).pages)
                self.documents.append(dict(entry,text=text,kind='pdf'));self._text(entry,text)
            elif ext in {'.png','.jpg','.jpeg'}:
                binary=shutil.which('tesseract') or ('C:/Program Files/Tesseract-OCR/tesseract.exe' if Path('C:/Program Files/Tesseract-OCR/tesseract.exe').exists() else None)
                if binary:
                    result=subprocess.run([binary,str(path),'stdout'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    if result.returncode:raise RuntimeError(result.stderr)
                    self.documents.append(dict(entry,text=result.stdout,kind='ocr'));self._text(entry,result.stdout)
                    # Sparse UI text can disappear when the default page segmenter
                    # groups table columns. Preserve this as an independent read.
                    sparse=subprocess.run([binary,str(path),'stdout','--psm','11'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    if sparse.returncode:self.issues.append({'file_id':entry['file_id'],'issue':'Sparse OCR failed'})
                    elif sparse.stdout!=result.stdout:self.documents.append(dict(entry,text=sparse.stdout,kind='ocr',extraction='sparse'))
                else:self.issues.append({'file_id':entry['file_id'],'issue':'OCR unavailable'})
            else:self.issues.append({'file_id':entry['file_id'],'issue':'unsupported extension'})
        except Exception as exc:
            self.issues.append({'file_id':entry['file_id'],'issue':str(exc)})

    def _json(self,entry,data):
        at=data.get('captured_at',data.get('exported_at',entry['captured_at']))
        if 'service_exports' in data:
            for system,collections in data['service_exports'].items():
                for collection,records in collections.items():
                    for i,r in enumerate(records):
                        self.add(entry,r,system,collection,at,locator=f'service_exports/{system}/{collection}/{i}')
            return
        if 'snapshots' in data:
            for i,snapshot in enumerate(data['snapshots']):
                for j,record in enumerate(snapshot.get('records',[])):
                    self.add(entry,record,snapshot.get('data_store',''),snapshot.get('collection',''),snapshot.get('captured_at',at),locator=f'snapshots/{i}/records/{j}')
            return
        records=data.get('records',[])
        for i,record in enumerate(records):self.add(entry,record,data.get('source',data.get('origin','')),data.get('collection',''),at,locator=f'records/{i}')

    def _sql(self,entry,text):
        # Isolated memory connection; reject attached files and loadable extensions.
        db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row
        db.set_authorizer(lambda action,a,b,c,d:sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_ATTACH or (action==sqlite3.SQLITE_FUNCTION and str(b).lower()=='load_extension') else sqlite3.SQLITE_OK)
        try:
            db.executescript(text)
            snapshot_time=re.search(r'Captured at:\s*('+ISO+')',text)
            tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            declared={r['origin_system']:r['captured_at'] for r in db.execute('SELECT * FROM snapshot_scope')} if 'snapshot_scope' in tables else {}
            for table in tables:
                if table=='snapshot_scope':continue
                quoted='"'+table.replace('"','""')+'"';rows=[dict(r) for r in db.execute('SELECT * FROM '+quoted)]
                spec=COLLECTIONS.get(table)
                if spec and spec[0] in declared:
                    self.scopes.append(dict(evidence_id=entry['file_id'],available_at=entry['captured_at'],observed_at=declared[spec[0]],system_id=spec[0],category=spec[1],scope='logical',resources={r.get('resource_id') for r in rows},complete=False))
                for row in rows:
                    record=json.loads(row['record_json']) if row.get('record_json') else dict(row)
                    record.update({k:v for k,v in row.items() if k!='record_json'})
                    system=row.get('origin_system',spec[0] if spec else 'account_service' if table.startswith('customer_profiles_') else '')
                    collection=row.get('collection_name',table)
                    physical=table if ('replica' in table or table.endswith('_primary')) else 'logical'
                    # updated_at is a row version time. Existence is read at the
                    # snapshot capture time, even when the row has not changed.
                    record['observed_at']=declared.get(system,snapshot_time[1] if snapshot_time else entry['captured_at'])
                    self.add(entry,record,system,collection,scope=physical,locator=table+'/'+str(row.get('resource_id','')))
        finally:db.close()

    @staticmethod
    def _kv(text):
        values={}
        for m in re.finditer(r'([A-Za-z_][\w.]*)=("(?:\\.|[^"\\])*"|\S+)',text):
            value=m.group(2)
            if value.startswith('"'):
                try:value=json.loads(value)
                except json.JSONDecodeError:value=value[1:-1]
            if str(value).lower()=='null':value=None
            values[m.group(1)]=value
        return values

    def _log(self,entry,text):
        starts={}
        for number,line in enumerate(text.splitlines(),1):
            time=re.search(ISO,line)
            if not time:continue
            at=time.group();rest=line[time.end():].strip();fields={}
            if rest.startswith('{'):
                try:fields=json.loads(rest)
                except json.JSONDecodeError:continue
            else:
                fields=self._kv(rest)
                if 'message' in fields:
                    fields.update(self._kv(str(fields.pop('message'))));fields.setdefault('service',fields.get('function',''));fields.setdefault('trace_id',fields.get('requestId',''))
                bracket=re.match(r'\[\w+\]\s+\[([^]]+)\]\s+\[([^]]+)\]\s+(\w+):',rest)
                pipe=[p.strip() for p in rest.split('|')]
                syslog=re.match(r'<\d+>\d+\s+\S+\s+(\S+)\s+(\S+)\s+-\s+-',rest)
                if bracket:fields.update(service=bracket[1],trace_id=bracket[2],event=bracket[3])
                elif len(pipe)>=6:fields.update(service=pipe[2],trace_id=pipe[3],event=pipe[4])
                elif syslog:fields.update(service=syslog[1],trace_id=syslog[2])
            service=fields.get('service','');event=fields.get('event','');trace=fields.get('trace_id','')
            join=(service,fields.get('instance',''),trace)
            if event.endswith(('_started','_begin')) and trace:starts[join]=(at,fields)
            if event.endswith(('_started','_begin')):continue
            if not fields.get('resource_id'):continue
            is_read=any(token in event for token in ('lookup_completed','query_completed','profile_read','profile_scan_completed','message_scan_completed','message_pii_scan','message_read','attachment_pii_scan','attachment_scan_completed','audit_record_read','config_read_completed','policy_read_completed','ticket_read_completed','export_read_completed','identity_scan','record_lookup','restore_access','restore_authorization_completed','download_check','export_metadata_read_completed'))
            # Require recognizable authoritative read fields. Auxiliary resource logs do not establish state.
            is_read=is_read or (event.endswith(('_completed','_read','_heartbeat')) and any(k in fields for k in ('enabled','restore_allowed','pii_matches','direct_identifiers','download_available','rows','integrity_check')))
            if not is_read:continue
            merged={}
            if join in starts and 0<=(timestamp(at)-timestamp(starts[join][0])).total_seconds()<=600:
                merged.update({k:v for k,v in starts[join][1].items() if k in IDENTITY_FIELDS})
            merged.update(fields)
            category=merged.get('record_type') or SYSTEM_CATEGORY.get(service,'')
            if 'attachment' in event:category='SUPPORT_ATTACHMENT'
            if 'tombstone' in event:category='ACCOUNT_TOMBSTONE'
            o=self.add(entry,merged,service,'',at,locator=f'line:{number}')
            if o:
                o.category=category;o.state=infer_state(category,merged)
                if 'replica' in service:o.scope=fields.get('instance',service)

    def _text(self,entry,text):
        for i,line in enumerate(text.splitlines(),1):
            parts=[p.strip() for p in line.lstrip('- ').split('|')]
            if len(parts)==6 and re.fullmatch(ISO,parts[0]):
                at,system,resource,category,result,subject=parts
                self.add(entry,dict(resource_id=resource,record_type=category,result=result,subject_reference=subject),system,'',at,locator=f'line:{i}')

    def _activities(self):
        for r in self.activities:
            details=r['details'];entry={'file_id':r['activity_id'],'captured_at':r['event_time']}
            keys=set(re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\buser_\d+\b|\b[a-f0-9]{64}\b',details,re.I))
            fields={'resource_id':r['resource_id'],'details':details,'event_type':r['event_type']}
            # Keep catalog membership and command claims separately from read observations.
            system=r['target_system'];category=SYSTEM_CATEGORY.get(system,'')
            state='';assertion='claim'
            if r['event_type']=='LINK_RESOURCE_IDENTITY':assertion='catalog'
            elif r['event_type']=='CHECK_DATA_FLOW' and 'remains enabled' in details:state='ACTIVE';category='DATA_FLOW';assertion='read'
            elif r['event_type']=='CHECK_RESTORE_ACCESS' and 'can still be restored' in details:state='ACTIVE';category='BACKUP_ARCHIVE';assertion='read'
            if r['resource_id']:
                self.observations.append(Observation(r['activity_id'],system,r['resource_id'],category,state,r['event_time'],r['event_time'],fields,{normalize(k) for k in keys},assertion=assertion))
            # Explicit resource identifiers in details provide grounded traversal links, never numeric suffix joins.
            linked=set(re.findall(r'\b(?:account|profile|search|analytics|support|attachment|export|backup|data_flow|audit_record|tombstone|order|cache|marketing|telemetry|delivery_log)_\d+\b',details))
            for resource in linked:
                if resource!=r['resource_id']:self.resource_links.append((r['resource_id'],resource,r['event_time'],r['event_time']))
