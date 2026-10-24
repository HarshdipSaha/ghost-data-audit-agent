"""Reconstruct audit-time obligations and compile policy-safe ordered decisions."""
import re
from collections import defaultdict
from dataclasses import replace
from datetime import datetime,timezone

from .contract import compile_steps
from .identity import IdentityResolver,normalize
from .ingest import Store,NULLS,truth,infer_state,ISO
from .models import AuditDecision,Observation,UnresolvedAudit,timestamp

ACTION_STEPS={
    'DELETE':('REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT','ABSENT'),
    'REDACT':('REPORT_EXPOSED_PII','REDACT_RECORD','VERIFY_RECORD_REDACTED','REDACTED'),
    'ANONYMIZE':('REPORT_EXPOSED_PII','ANONYMIZE_RECORD','VERIFY_RECORD_ANONYMIZED','ANONYMIZED'),
    'RETAIN':(None,None,'VERIFY_RECORD_PRESENT','PRESENT'),
    'DISABLE':('REPORT_ACTIVE_DATA_FLOW','DISABLE_DATA_FLOW','VERIFY_DATA_FLOW_DISABLED','DISABLED'),
    'BLOCK':('REPORT_RESTORE_RISK','BLOCK_RESTORE','VERIFY_RESTORE_BLOCKED','BLOCKED'),
}
NO_OBLIGATION='NO_OBLIGATION'
UNSPECIFIED_POLICY='UNSPECIFIED_POLICY'


def _document_state_asserted(state,quote):
    """Accept a model's cited state only when the quote asserts it affirmatively."""
    text=re.sub(r'\s+',' ',str(quote)).casefold().strip()
    if not text:return False
    patterns={
        'PRESENT':r'\b(?:exists?|present|found|contains?|containing|includes?|shows?|lists?|has|matched|identified|exposes?|retains?|remains?)\b',
        'REDACTED':r'\b(?:redacted|masked|scrubbed|removed|replaced with (?:a )?(?:placeholder|token))\b',
        'ANONYMIZED':r'\b(?:anonymi[sz]ed|de[- ]identified|unlinked|irreversibly anonymi[sz]ed)\b',
        'ABSENT':r'\b(?:not found|no (?:matching )?(?:records?|rows?|results?|entries?)|zero (?:records?|rows?|results?|entries?)|absent|does not exist|was deleted)\b',
        'BLOCKED':r'\b(?:blocked|denied|prevented|prohibited)\b',
        'DISABLED':r'\b(?:disabled|inactive|shut off|turned off)\b',
        'ACTIVE':r'\b(?:enabled|active|running|continuous sync|processing)\b',
    }
    if state not in patterns:return False
    matches=list(re.finditer(patterns[state],text))
    if not matches:return False
    for match in matches:
        before=text[max(0,match.start()-48):match.start()]
        after=text[match.end():match.end()+32]
        # State-specific contradictions. `not found` is affirmative evidence for
        # ABSENT, while `not absent` and the other forms below negate the state.
        if state=='PRESENT':
            if re.search(r'\b(?:no|not|never|without|absent|missing|deleted|redacted|anonymi[sz]ed)\b(?:\s+\w+){0,4}\s*$',before):continue
            if re.search(r'\b(?:no|not|never|without)\b.{0,36}\b(?:record|profile|identifier|data|email|phone)\b',before):continue
        elif state=='REDACTED':
            if re.search(r'\b(?:not|never|still|yet|un)\b(?:\s+\w+){0,3}\s*$',before) or re.match(r'\s*(?:false|=\s*false)\b',after):continue
        elif state=='ANONYMIZED':
            if re.search(r'\b(?:not|never|still|yet|un)\b(?:\s+\w+){0,3}\s*$',before):continue
        elif state=='ABSENT':
            if re.search(r'\b(?:not|never|no longer)\b(?:\s+\w+){0,3}\s*$',before) and match.group(0)!='not found':continue
            if re.match(r'\s*(?:false|=\s*false)\b',after):continue
        elif state=='BLOCKED':
            if re.search(r'\b(?:not|never|no longer|un)\b(?:\s+\w+){0,3}\s*$',before) or re.search(r'\b(?:allowed|permitted)\b',text):continue
        elif state=='DISABLED':
            if re.search(r'\b(?:not|never|no longer|un)\b(?:\s+\w+){0,3}\s*$',before) or re.search(r'\benabled\s*[:=]\s*(?:true|1|yes)\b',text):continue
        elif state=='ACTIVE':
            if re.search(r'\b(?:not|never|no longer|un)\b(?:\s+\w+){0,3}\s*$',before):continue
            if re.search(r'\benabled\s*[:=]\s*(?:false|0|no)\b|\b(?:disabled|inactive|stopped|paused)\b',text):continue
            if re.match(r'\s*[:=]\s*(?:false|0|no)\b',after):continue
        return True
    return False


def _positive_text_evidence(pattern,text):
    """Find a phrase unless the same sentence explicitly negates it."""
    for match in re.finditer(pattern,text):
        sentence=text[max(text.rfind('.',0,match.start()),text.rfind(';',0,match.start()),text.rfind('\n',0,match.start()))+1:match.start()]
        # This phrase uses "no" to establish exclusivity, so it is positive proof.
        if match.group(0).casefold().startswith('no other subject is linked'):
            return True
        if not re.search(r'\b(?:no|not|never|without|doesn\'t|does not|isn\'t|is not|wasn\'t|was not)\b(?:\s+\w+){0,5}\s*$',sentence):
            return True
    return False


class Auditor:
    def __init__(self,dataset_path):
        self.store=Store(dataset_path)
        self.identity=IdentityResolver(self.store.identities,self.store.history)
        self.rules={r['data_category']:r for r in self.store.rules}

    def _discover(self,subject,cutoff):
        resources=set()
        for key in subject.aliases:
            resources.update(o.resource_id for o in self.store.by_identity.get(key,[]) if o.eligible(cutoff) and self.identity.belongs(o,subject,cutoff))
        changed=True
        while changed:
            before=len(resources)
            for a,b,available,observed in self.store.resource_links:
                if max(timestamp(available),timestamp(observed))<=timestamp(cutoff) and (a in resources or b in resources):
                    for linked in (a,b):
                        owners=[o for o in self.store.by_resource.get(linked,[]) if o.eligible(cutoff) and self.identity.explicit_owners(o)]
                        if not owners or any(self.identity.belongs(o,subject,cutoff) for o in owners):resources.add(linked)
            # A typed resource lookup can use another grounded resource as its identity key.
            for resource in list(resources):
                resources.update(o.resource_id for o in self.store.by_identity.get(normalize(resource),[]) if o.eligible(cutoff) and (self.identity.belongs(o,subject,cutoff) or not self.identity.explicit_owners(o)))
            changed=len(resources)>before
        return resources

    def _document_reads(self,resources,cutoff,semantic,subject=None):
        observations=[];rounds=0
        for doc in self.store.documents:
            if timestamp(doc['captured_at'])>timestamp(cutoff):continue
            text=doc['text']
            text=re.sub(r'(\d{1,2} [A-Za-z]{3} \d{4} \d{2})\s*\n\s*(\d{2}\s*UTC)',r'\1:\2',text)
            normalized=re.sub(r'\s+',' ',text).casefold()
            # Availability is separate from the state time printed in the artifact.
            fact_time=re.search(r'(?:observed(?: at)?|captured(?: at)?|as of|generated|issued|executed)\s*[:=]?\s*('+ISO+')',text,re.I)
            times=re.findall(ISO,text)
            observed=fact_time[1] if fact_time else times[0] if times else ''
            if not observed:
                human=re.search(r'\b(\d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}(?::\d{2})?)\s*UTC',normalized,re.I)
                if human:
                    for fmt in ('%d %b %Y %H:%M','%d %b %Y %H:%M:%S'):
                        try:observed=datetime.strptime(human[1],fmt).replace(tzinfo=timezone.utc).isoformat();break
                        except ValueError:pass
            if observed and timestamp(observed)>timestamp(cutoff):continue
            for resource in sorted(resources):
                catalog=[o for o in self.store.by_resource[resource] if o.assertion=='catalog' and o.eligible(cutoff)]
                descriptors=[]
                for c in catalog:
                    descriptors.extend(re.findall(r'\(([^)]+)\)',c.fields.get('details','')))
                resource_pattern=r'(?<![\w])'+r'[\s_.-]*'.join(re.escape(p) for p in resource.casefold().split('_'))+r'(?![\w])'
                grounded=re.search(resource_pattern,normalized)
                if not grounded:
                    for descriptor in descriptors:
                        if not descriptor.strip() or '@' in descriptor:continue
                        candidate=re.search(r'(?<![\w])'+re.escape(descriptor.casefold())+r'(?![\w])',normalized)
                        if candidate:grounded=candidate;break
                if not grounded:continue
                candidates=[o for o in self.store.by_resource[resource] if o.eligible(cutoff)]
                if not candidates:continue
                base=max(candidates,key=lambda o:timestamp(o.observed_at))
                category=base.category;system=base.system_id
                if system=='object_storage':category='SUPPORT_ATTACHMENT'
                if system=='identity_service':category='ACCOUNT_TOMBSTONE'
                if system=='marketing_platform':category='MARKETING_PROFILE'
                # Resource membership alone is never a row read. Require fields or a
                # visible business panel tied to that resource, not a catalog mention.
                fields=Store._kv(text)
                if fields.get('resource_id') and normalize(fields['resource_id'])!=normalize(resource):
                    rows=[Store._kv(line) for line in text.splitlines() if re.search(resource_pattern,line.casefold())]
                    fields=next((row for row in rows if normalize(row.get('resource_id'))==normalize(resource)),{})
                    if not fields:continue
                panel=normalized[max(0,grounded.start()-160):grounded.end()+1600]
                catalog_only=bool(re.search(r'resource catalog|data catalog|catalog linked',panel))
                row_fields=any(k in fields for k in ('email','phone','name','enabled','restore_allowed','rows','result','account_status','retention_until'))
                panel_read=bool(re.search(r'raw document|customer details|profile attributes|message|conversation|archive path|file size|object properties|integrity seal|event reference|connector details|filename|file name',panel))
                state=''
                if not catalog_only and (row_fields or panel_read):
                    if row_fields:state=infer_state(category,fields)
                    elif category in {'USER_PROFILE','SEARCH_INDEX_ENTRY','USER_EXPORT','MARKETING_PROFILE','SUPPORT_MESSAGE','SUPPORT_ATTACHMENT','ANALYTICS_PROFILE'} and re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}',panel):state='PRESENT'
                    elif category=='SECURITY_AUDIT_LOG' and re.search(r'event reference\s+'+resource_pattern,panel) and re.search(r'integrity seal\s+valid',panel):state='PRESENT'
                retention=re.search(r'retain until\s+(\d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2})\s*UTC',panel,re.I)
                if retention:
                    fields['retention_until']=datetime.strptime(retention[1],'%d %b %Y %H:%M').replace(tzinfo=timezone.utc).isoformat()
                # A selected connector panel reports observed runtime state through
                # its selector, continuous mode and successful recent response.
                selector=re.search(r'selector\s+([\w.+-]+@[\w.-]+\.[a-z]{2,})',panel)
                runtime=re.search(r'continuous sy(?:nc|ne)',panel) and re.search(r'last response\s+200\s*(?:ok|0k)',panel)
                if category=='DATA_FLOW' and not catalog_only and selector and runtime and (subject is None or normalize(selector[1]) in subject.aliases):
                    state='ACTIVE';fields.update(subject_selector=selector[1],enabled=True)
                if not state and semantic is not None and rounds<3:
                    rounds+=1
                    result=semantic.interpret_evidence(text[:8000],doc['file_id'],[resource])
                    quote=str(result.get('quote',''));proposed=result.get('state','UNRESOLVED')
                    normalized_quote=re.sub(r'\s+',' ',quote).casefold()
                    if result.get('resource_id')==resource and normalized_quote and normalized_quote in normalized:
                        if re.search(resource_pattern,normalized_quote) and _document_state_asserted(proposed,normalized_quote) and (row_fields or panel_read):state=proposed
                # A screenshot is a state snapshot only when its UI explicitly says
                # it is current. Undated narrative artifacts remain unresolved.
                if not observed and doc.get('kind')=='ocr' and re.search(r'updated moments ago|production.{0,30}\d{4}',normalized):observed=doc['captured_at']
                if state and observed:
                    fields=dict(fields,text=text)
                    emails={normalize(e) for e in re.findall(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}',normalized)}
                    if subject and emails and not emails.intersection(subject.aliases):
                        fields['identity_conflict']='Visible email differs from target aliases; independent catalog/resource link establishes association. No alias expansion.'
                    observations.append(Observation(doc['file_id'],system,resource,category,state,observed,doc['captured_at'],fields,set(),locator='document'))
        return observations,rounds

    def _action(self,category,observation,cutoff):
        if category=='DATA_FLOW':return 'DISABLE'
        rule=self.rules.get(category)
        if not rule:return None
        condition=rule.get('condition','').strip().casefold();fields=observation.fields
        if condition=='always':return rule['required_action']
        text=' '.join(str(fields.get(k,'')) for k in ('text','details','message_text','message_excerpt','retention_reason')).casefold()
        established=False
        if category=='SUPPORT_MESSAGE' and 'shared' in condition:
            explicit=truth(fields.get('shared_context'))
            order_reference=normalize(fields.get('order_reference')) not in NULLS
            structured=bool(re.search(r'\b(?:order_reference|order_id)\s*[:=]\s*[a-z0-9_-]+\b',text))
            contextual=_positive_text_evidence(r'\bshared\s+(?:customer|agent|order)\s+context\b|\b(?:customer\s+and\s+agent|agent\s+and\s+customer)\s+(?:conversation|message|context|discussed)\b|\b(?:affected|customer|purchase)\s+order\b|\border\s+(?:reference|id|number)\s*[:#-]?\s*[a-z0-9_-]+\b',text)
            positive=order_reference or structured or contextual or explicit is True
            negative=explicit is False or _positive_text_evidence(r'\b(?:no shared context|private message|no order (?:context|exists)|agent was not involved)\b',text)
            if positive and negative:return None
            if negative:return UNSPECIFIED_POLICY
            established=positive
        elif category=='SUPPORT_ATTACHMENT' and 'belongs only' in condition:
            exclusive=truth(fields.get('exclusive_subject'))
            text_proof=_positive_text_evidence(r'\bbelongs only to (?:the )?(?:deletion )?subject\b|\bno other subject is linked\b|\bexclusive(?:ly)? assigned to (?:the )?(?:deletion )?subject\b',text)
            negative=exclusive is False or bool(re.search(r'\b(?:does not belong only|not exclusive|not solely|another subject is linked|other subjects are linked)\b|(?<!no )\bother subject is linked\b',text))
            positive=exclusive is True or text_proof
            if negative and positive:return None
            if negative:return UNSPECIFIED_POLICY
            established=positive
        elif category in {'ANALYTICS_PROFILE','PRODUCT_TELEMETRY'} and ('attributable' in condition or condition=='attributable'):
            attributable=truth(fields.get('attributable'))
            direct_identifiers=truth(fields.get('direct_identifiers'))
            identity_present=any(normalize(fields.get(k)) not in NULLS for k in ('email','phone','email_hash','user_id','customer_reference','subject_reference'))
            if attributable is False and not identity_present and direct_identifiers is not True:return NO_OBLIGATION
            established=observation.state=='ANONYMIZED' or attributable is True or identity_present or direct_identifiers is True
        elif category=='EMAIL_DELIVERY_LOG' and 'email address' in condition:
            established=observation.state=='REDACTED' or any(re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}',str(v),re.I) for v in fields.values())
        elif category=='SECURITY_AUDIT_LOG' and ('retention' in condition):
            until=fields.get('retention_until');start=fields.get('retention_from',fields.get('retention_start'))
            if start and timestamp(start)>timestamp(cutoff):return UNSPECIFIED_POLICY
            if until and timestamp(cutoff)>timestamp(until):return UNSPECIFIED_POLICY
            established=bool(until and timestamp(cutoff)<=timestamp(until))
        elif category=='LEGAL_HOLD_RECORD' and 'legal hold' in condition:
            until=fields.get('retained_until',fields.get('hold_until'));start=fields.get('hold_from')
            active=truth(fields.get('legal_hold_active',fields.get('hold_active')))
            if active is False:return UNSPECIFIED_POLICY
            if start and timestamp(start)>timestamp(cutoff):return UNSPECIFIED_POLICY
            if until and timestamp(cutoff)>timestamp(until):return UNSPECIFIED_POLICY
            interval=True
            established=interval and active is not False and (active is True or bool(until and fields.get('retention_reason')))
        elif category=='ACCOUNT_TOMBSTONE' and 'stable' in condition:
            stable_value=next((fields.get(k) for k in ('user_id','subject_reference','customer_reference') if normalize(fields.get(k)) not in NULLS),None)
            stable=bool(stable_value) and '@' not in str(stable_value) and not re.fullmatch(r'[+\d ()-]{7,}',str(stable_value))
            retained_ids=fields.get('retained_record_ids',fields.get('retained_order_ids'))
            structured=truth(fields.get('retained_references')) is True or (bool(retained_ids) and normalize(retained_ids) not in NULLS) or normalize(fields.get('order_reference')) not in NULLS
            textual=_positive_text_evidence(r'\b(?:retained reference|linked records|preserve references)\b',text)
            negative_reference=bool(re.search(r'\b(?:no linked records|no references to preserve|no retained references|without (?:any )?references)\b',text))
            references=structured or textual
            if structured and negative_reference:return None
            if not structured and negative_reference:return None
            established=str(fields.get('account_status','')).upper() in {'DELETED','DELETED_TOMBSTONE'} and stable and references
        elif category=='BACKUP_ARCHIVE' and ('restore' in condition):
            if observation.state in {'BLOCKED','ACTIVE'} or truth(fields.get('restore_block_supported')) is True:return 'BLOCK'
        return rule['required_action'] if established else None

    def audit(self,request,authorization,semantic=None):
        case=request['case_id']
        if authorization is False:return AuditDecision(case,'NOT_APPLICABLE',[],{'authorized':False})
        if authorization is not True:raise UnresolvedAudit(case,{'authorization':'not a boolean decision'})
        cutoff=request['audit_at']
        try:subject=self.identity.resolve(request['email'],cutoff)
        except UnresolvedAudit as exc:raise UnresolvedAudit(case,exc.details) from exc
        resources=self._discover(subject,cutoff)
        if not resources:raise UnresolvedAudit(case,{'identity':subject.user_id,'issue':'No grounded resources discovered'})
        document_reads,rounds=self._document_reads(resources,cutoff,semantic,subject)
        grouped=defaultdict(list)
        unknown=[]
        for resource in sorted(resources):
            candidates=[o for o in self.store.by_resource.get(resource,[]) if o.eligible(cutoff)]
            candidates=[o for o in candidates if not self.identity.explicit_owners(o) or self.identity.belongs(o,subject,cutoff)]
            reads=[o for o in candidates if o.assertion=='read']+[o for o in document_reads if o.resource_id==resource]
            categories={o.category for o in candidates if o.category}
            if not reads:
                unknown.append({'resource_id':resource,'issue':'No timely authoritative state read'})
                continue
            # A complete SQL service inventory can establish absence only for a resource
            # independently grounded to that service/category before the snapshot.
            for scope in self.store.scopes:
                # Supplied snapshot_scope names services, but does not assert global
                # completeness or the absence of unlisted subjects in a batch.
                if not scope.get('complete'):continue
                if resource in scope['resources'] or max(timestamp(scope['available_at']),timestamp(scope['observed_at']))>timestamp(cutoff):continue
                grounded=[o for o in candidates if o.system_id==scope['system_id'] and o.category==scope['category'] and timestamp(o.observed_at)<=timestamp(scope['observed_at'])]
                if grounded:
                    reads.append(Observation(scope['evidence_id'],scope['system_id'],resource,scope['category'],'ABSENT',scope['observed_at'],scope['available_at'],{},set(),scope['scope'],locator='scoped SQL inventory'))
            for o in reads:
                category=o.category
                if not category and len(categories)==1:category=next(iter(categories))
                if not category:
                    unknown.append({'resource_id':resource,'issue':'Unknown category'});continue
                # Primary readback observations describe the logical primary. Replica scopes
                # remain independent and survive a clean primary read.
                scope='logical' if o.scope.endswith('_primary') else o.scope
                grouped[(o.system_id,resource,category,scope)].append(o)
        latest={}
        for key,observations in grouped.items():
            latest[key]=max(observations,key=lambda o:(timestamp(o.observed_at),timestamp(o.available_at),o.evidence_id))
        obligations=defaultdict(list)
        for (system,resource,category,scope),o in latest.items():
            policy_fields={};policy_sources=[]
            for fact in sorted(self.store.by_resource[resource],key=lambda x:timestamp(x.observed_at)):
                if fact.eligible(cutoff) and fact.assertion in {'read','catalog'} and (not self.identity.explicit_owners(fact) or self.identity.belongs(fact,subject,cutoff)):
                    policy_fields.update(fact.fields);policy_sources.append(fact.evidence_id)
            policy_fields.update(o.fields)
            action=self._action(category,replace(o,fields=policy_fields),cutoff)
            if action==NO_OBLIGATION:continue
            if action==UNSPECIFIED_POLICY:
                unknown.append({'resource_id':resource,'category':category,'evidence_id':o.evidence_id,'issue':'Policy predicate is false but fallback treatment is not supplied'})
                continue
            if not action:
                unknown.append({'resource_id':resource,'category':category,'issue':'Policy obligation unresolved'});continue
            if not o.state:
                unknown.append({'resource_id':resource,'category':category,'evidence_id':o.evidence_id,'issue':'Read does not establish required treatment'});continue
            expected=ACTION_STEPS[action][3]
            if action=='RETAIN' and o.state=='ABSENT':
                unknown.append({'resource_id':resource,'issue':'Required retained record absent; no permitted restore remediation in contract'});continue
            obligations[(system,resource,action)].append((o,o.state==expected))
            if category=='BACKUP_ARCHIVE':
                if o.state=='ABSENT' or truth(o.fields.get('archive_present')) is False:
                    unknown.append({'resource_id':resource,'issue':'Required retained archive absent'})
                else:
                    # A restore-entry read or explicit archive state establishes archive
                    # presence independently from whether restores are allowed.
                    obligations[(system,resource,'RETAIN')].append((o,True))
        if unknown:raise UnresolvedAudit(case,{'subject':subject.user_id,'resources':len(resources),'unresolved':unknown,'semantic_rounds':rounds})
        if not obligations:raise UnresolvedAudit(case,{'issue':'No policy obligations established'})
        incomplete=any(not all(ok for _,ok in values) for values in obligations.values())
        steps=[]
        def add(phase,system,resource,operation,state,evidence=''):
            steps.append(dict(phase=phase,system_id=system,resource_id=resource,operation=operation,state=state,evidence_id=evidence))
        for (system,resource,action),values in obligations.items():
            finding,remediation,verification,expected=ACTION_STEPS[action]
            dirty=[o for o,ok in values if not ok]
            if dirty:
                o=max(dirty,key=lambda o:(timestamp(o.observed_at),timestamp(o.available_at),o.evidence_id))
                add('FINDING',system,resource,finding,'ACTIVE' if action in {'DISABLE','BLOCK'} else 'PRESENT',o.evidence_id)
                add('REMEDIATION',system,resource,remediation,expected)
            if incomplete:
                add('VERIFICATION',system,resource,verification,expected)
            else:
                # Each latest physical obligation needs its own admissible witness.
                # One citation cannot stand in for another replica's state read.
                for proof,_ in sorted(values,key=lambda value:(value[0].scope,value[0].evidence_id)):
                    add('VERIFICATION',system,resource,verification,expected,proof.evidence_id)
        conflicts=[{'resource_id':o.resource_id,'evidence_id':o.evidence_id,'issue':o.fields['identity_conflict']} for o in document_reads if o.fields.get('identity_conflict')]
        return AuditDecision(case,'INCOMPLETE' if incomplete else 'COMPLETE',compile_steps(steps),{'subject':subject.user_id,'resource_count':len(resources),'obligation_count':len(obligations),'semantic_rounds':rounds,'identity_conflicts':conflicts})
