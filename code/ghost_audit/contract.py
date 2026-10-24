import csv
import json
from .models import timestamp

OPERATIONS = {
    'FINDING': [('REPORT_REMAINING_RECORD','PRESENT'),('REPORT_EXPOSED_PII','PRESENT'),('REPORT_ACTIVE_DATA_FLOW','ACTIVE'),('REPORT_RESTORE_RISK','ACTIVE')],
    'REMEDIATION': [('DISABLE_DATA_FLOW','DISABLED'),('BLOCK_RESTORE','BLOCKED'),('DELETE_RECORD','ABSENT'),('REDACT_RECORD','REDACTED'),('ANONYMIZE_RECORD','ANONYMIZED')],
    'VERIFICATION': [('VERIFY_RECORD_ABSENT','ABSENT'),('VERIFY_RECORD_PRESENT','PRESENT'),('VERIFY_RECORD_REDACTED','REDACTED'),('VERIFY_RECORD_ANONYMIZED','ANONYMIZED'),('VERIFY_DATA_FLOW_DISABLED','DISABLED'),('VERIFY_RESTORE_BLOCKED','BLOCKED')],
}
FIELDS = {'step_no','phase','system_id','resource_id','operation','state','evidence_id'}


def step_key(s):
    return (list(OPERATIONS).index(s['phase']),[p[0] for p in OPERATIONS[s['phase']]].index(s['operation']),s['system_id'],s['resource_id'])


def compile_steps(steps):
    return [dict(s,step_no=i) for i,s in enumerate(sorted(steps,key=step_key),1)]


def validate_row(row,evidence_times=None,audit_at=None):
    if set(row)!={'case_id','deletion_status','steps_json'}: raise ValueError('Invalid output columns')
    status=row['deletion_status']; steps=json.loads(row['steps_json']) if isinstance(row['steps_json'],str) else row['steps_json']
    if status not in {'COMPLETE','INCOMPLETE','NOT_APPLICABLE'} or not isinstance(steps,list): raise ValueError('Invalid status or steps')
    if status=='NOT_APPLICABLE' and steps: raise ValueError('Non deletion steps must be empty')
    if status in {'COMPLETE','INCOMPLETE'} and not steps: raise ValueError('Authorized audits require evidence')
    for i,s in enumerate(steps,1):
        if set(s)!=FIELDS or s['step_no']!=i or (s['operation'],s['state']) not in OPERATIONS.get(s['phase'],[]): raise ValueError('Invalid step')
        if not s['system_id'] or not s['resource_id']: raise ValueError('Missing resource')
        needs=s['phase']=='FINDING' or status=='COMPLETE'
        if bool(s['evidence_id'])!=needs: raise ValueError('Invalid evidence placement')
        if status=='COMPLETE' and s['phase']!='VERIFICATION': raise ValueError('Complete requires verification only')
        if needs and evidence_times is not None:
            if s['evidence_id'] not in evidence_times: raise ValueError('Unknown citation')
            if audit_at and timestamp(evidence_times[s['evidence_id']])>timestamp(audit_at): raise ValueError('Future citation')
    if steps!=compile_steps(steps): raise ValueError('Noncanonical order')
    if status=='INCOMPLETE' and not any(s['phase']=='FINDING' for s in steps): raise ValueError('Missing findings')
    return True


def write_output(path,decisions):
    rows=[]
    for d in sorted(decisions,key=lambda d:d.case_id):
        row=dict(case_id=d.case_id,deletion_status=d.status,steps_json=json.dumps(d.steps,separators=(',',':'),ensure_ascii=False));validate_row(row);rows.append(row)
    if len({r['case_id'] for r in rows})!=len(rows): raise ValueError('Duplicate cases')
    with open(path,'w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json']);w.writeheader();w.writerows(rows)
