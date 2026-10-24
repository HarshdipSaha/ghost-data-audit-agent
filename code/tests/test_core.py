import json
import tempfile
import unittest
import sys
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ghost_audit.contract import compile_steps, validate_row
from ghost_audit.ingest import Store,infer_state,keys_from
from ghost_audit.identity import IdentityResolver
from ghost_audit.engine import Auditor,_document_state_asserted
from ghost_audit.models import UnresolvedAudit,Observation


class CoreTests(unittest.TestCase):
    def test_tombstone_requires_stable_reference_and_complete_identifier_coverage(self):
        self.assertEqual(infer_state('ACCOUNT_TOMBSTONE',dict(email=None,phone=None,email_hash=None)),'')
        clean=dict(subject_reference='u',account_status='DELETED',name=None,email=None,phone=None,email_hash=None)
        self.assertEqual(infer_state('ACCOUNT_TOMBSTONE',clean),'REDACTED')
        self.assertEqual(infer_state('ACCOUNT_TOMBSTONE',dict(clean,subject_reference=None)),'')
        self.assertEqual(infer_state('ACCOUNT_TOMBSTONE',dict(clean,owner_email='other@example.com')),'PRESENT')

    def test_policy_conditions_need_resource_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            conditions={
                'SUPPORT_MESSAGE':('Conversation contains shared customer, agent, or order context that must be retained','REDACT',{'shared_context':True}),
                'SUPPORT_ATTACHMENT':('Attachment belongs only to the deletion subject','DELETE',{'exclusive_subject':True}),
                'ANALYTICS_PROFILE':('Record is still attributable to a user','ANONYMIZE',{'email':'old@example.com'}),
                'SECURITY_AUDIT_LOG':('Record is within the supplied retention period','RETAIN',{'retention_until':'2027-01-01T00:00:00Z'}),
                'LEGAL_HOLD_RECORD':('A supplied legal hold is active','RETAIN',{'legal_hold_active':True}),
                'ACCOUNT_TOMBSTONE':('Account is deleted and only a stable internal user_id is needed to preserve references to retained records','REDACT',{'account_status':'DELETED','subject_reference':'u','retained_references':True}),
            }
            for category,(condition,action,fields) in conditions.items():
                auditor.rules[category]={'condition':condition,'required_action':action}
                o=Observation('e','s','r',category,'PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')
                with self.subTest(category=category):
                    self.assertIsNone(auditor._action(category,o,'2026-01-02T00:00:00Z'))
                    o.fields=fields
                    self.assertEqual(auditor._action(category,o,'2026-01-02T00:00:00Z'),action)
            auditor.rules['USER_PROFILE']={'condition':'Some unknown condition','required_action':'DELETE'}
            self.assertIsNone(auditor._action('USER_PROFILE',o,'2026-01-02T00:00:00Z'))

    def test_support_policy_ignores_negation_and_null_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['SUPPORT_MESSAGE']={'condition':'Conversation contains shared customer, agent, or order context that must be retained','required_action':'REDACT'}
            o=Observation('e','support_platform','message_1','SUPPORT_MESSAGE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')
            for fields,expected in (
                ({'text':'No order context; this is a private customer message.'},'UNSPECIFIED_POLICY'),
                ({'order_reference':'null'},None),
                ({'text':'The agent was not involved and no order exists.'},'UNSPECIFIED_POLICY'),
            ):
                o.fields=fields
                with self.subTest(fields=fields):self.assertEqual(auditor._action(o.category,o,'2026-01-02T00:00:00Z'),expected)
            o.fields={'text':'The customer and agent discussed order reference ORD-17.'}
            self.assertEqual(auditor._action(o.category,o,'2026-01-02T00:00:00Z'),'REDACT')
            o.fields={'ticket_id':'CS-17','channel':'email','message_text':'Please send the delivery update.'}
            self.assertIsNone(auditor._action(o.category,o,'2026-01-02T00:00:00Z'))
            o.fields={'ticket_id':'CS-17','channel':'email','message_text':'The customer and agent discussed order reference ORD-17.'}
            self.assertEqual(auditor._action(o.category,o,'2026-01-02T00:00:00Z'),'REDACT')

            auditor.rules['SUPPORT_ATTACHMENT']={'condition':'Attachment belongs only to the deletion subject','required_action':'DELETE'}
            attachment=Observation('e','support_platform','attachment_1','SUPPORT_ATTACHMENT','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{'text':'This attachment does not belong only to the subject.'})
            self.assertEqual(auditor._action(attachment.category,attachment,'2026-01-02T00:00:00Z'),'UNSPECIFIED_POLICY')
            attachment.fields={'text':'No other subject is linked to this attachment.'}
            self.assertEqual(auditor._action(attachment.category,attachment,'2026-01-02T00:00:00Z'),'DELETE')

    def test_false_policy_predicates_are_distinct_from_missing_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['SUPPORT_MESSAGE']={'condition':'Conversation contains shared customer, agent, or order context that must be retained','required_action':'REDACT'}
            message=Observation('e','support_platform','m','SUPPORT_MESSAGE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{'shared_context':False})
            self.assertEqual(auditor._action('SUPPORT_MESSAGE',message,'2026-01-02T00:00:00Z'),'UNSPECIFIED_POLICY')
            message.fields={}
            self.assertIsNone(auditor._action('SUPPORT_MESSAGE',message,'2026-01-02T00:00:00Z'))
            message.fields={'shared_context':False,'order_reference':'ORD-17'}
            self.assertIsNone(auditor._action('SUPPORT_MESSAGE',message,'2026-01-02T00:00:00Z'))

    def test_non_boolean_direct_identifier_values_do_not_establish_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['ANALYTICS_PROFILE']={'condition':'Record is still attributable to a user','required_action':'ANONYMIZE'}
            observation=Observation('e','analytics_platform','a','ANALYTICS_PROFILE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')
            for value,expected in (('false',None),('no',None),('null',None),('0',None),('',None)):
                observation.fields={'direct_identifiers':value}
                with self.subTest(value=value):
                    self.assertEqual(auditor._action('ANALYTICS_PROFILE',observation,'2026-01-02T00:00:00Z'),expected)
            observation.fields={'direct_identifiers':'true'}
            self.assertEqual(auditor._action('ANALYTICS_PROFILE',observation,'2026-01-02T00:00:00Z'),'ANONYMIZE')
            observation.fields={'attributable':False}
            self.assertEqual(auditor._action('ANALYTICS_PROFILE',observation,'2026-01-02T00:00:00Z'),'NO_OBLIGATION')
            observation.fields={'attributable':False,'user_id':'u'}
            self.assertEqual(auditor._action('ANALYTICS_PROFILE',observation,'2026-01-02T00:00:00Z'),'ANONYMIZE')
            observation.fields={'direct_identifiers':'false','user_id':'u'}
            self.assertEqual(auditor._action('ANALYTICS_PROFILE',observation,'2026-01-02T00:00:00Z'),'ANONYMIZE')

    def test_conflicting_attachment_flags_and_text_remain_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['SUPPORT_ATTACHMENT']={'condition':'Attachment belongs only to the deletion subject','required_action':'DELETE'}
            attachment=Observation('e','support_platform','a','SUPPORT_ATTACHMENT','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{
                'exclusive_subject':False,'text':'No other subject is linked to this attachment.'
            })
            self.assertIsNone(auditor._action('SUPPORT_ATTACHMENT',attachment,'2026-01-02T00:00:00Z'))

    def test_tombstone_negated_retained_references_do_not_establish_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['ACCOUNT_TOMBSTONE']={'condition':'Account is deleted and only a stable internal user_id is needed to preserve references to retained records','required_action':'REDACT'}
            tombstone=Observation('e','identity_service','t','ACCOUNT_TOMBSTONE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{
                'user_id':'u','account_status':'DELETED','text':'No linked records remain; no references to preserve.'
            })
            self.assertIsNone(auditor._action('ACCOUNT_TOMBSTONE',tombstone,'2026-01-02T00:00:00Z'))

    def test_model_proposed_document_states_require_positive_non_negated_evidence(self):
        cases=(
            ('PRESENT','resource r: customer profile exists',True),
            ('PRESENT','resource r: no record exists',False),
            ('REDACTED','resource r identifiers are redacted',True),
            ('REDACTED','resource r identifiers are not redacted',False),
            ('ANONYMIZED','resource r is anonymized and unlinked',True),
            ('ANONYMIZED','resource r is not anonymized',False),
            ('ABSENT','resource r was not found',True),
            ('ABSENT','resource r is not absent',False),
            ('BLOCKED','resource r restore access is blocked',True),
            ('BLOCKED','resource r restore is not blocked',False),
            ('DISABLED','resource r process is disabled',True),
            ('DISABLED','resource r process is not disabled',False),
            ('ACTIVE','resource r connector is enabled',True),
            ('ACTIVE','resource r enabled=false',False),
        )
        for state,quote,expected in cases:
            with self.subTest(state=state,quote=quote):
                self.assertEqual(_document_state_asserted(state,quote),expected)

    def test_tombstone_reference_can_be_grounded_without_synthetic_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['ACCOUNT_TOMBSTONE']={'condition':'Account is deleted and only a stable internal user_id is needed to preserve references to retained records','required_action':'REDACT'}
            o=Observation('e','account_service','tombstone_1','ACCOUNT_TOMBSTONE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{
                'user_id':'user_17','account_status':'DELETED','order_reference':'ORD-17',
            })
            self.assertEqual(auditor._action(o.category,o,'2026-01-02T00:00:00Z'),'REDACT')

    def test_discovery_rejects_other_owner_and_recycled_identifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='account_service',resource_id='ours',record_type='USER_PROFILE',email='old@example.com',user_id='u'),dict(system='account_service',resource_id='theirs',record_type='USER_PROFILE',email='old@example.com',user_id='v')])
            auditor=Auditor(root);subject=auditor.identity.resolve('old@example.com','2026-01-02T00:00:00Z')
            self.assertEqual(auditor._discover(subject,'2026-01-02T00:00:00Z'),{'ours'})
            auditor.store.resource_links.append(('ours','theirs','2026-01-01T12:00:00Z','2026-01-01T10:00:00Z'))
            self.assertEqual(auditor._discover(subject,'2026-01-02T00:00:00Z'),{'ours'})
            rows=[dict(user_id='u',email='fresh@example.com'),dict(user_id='v',email='old@example.com')]
            history=[dict(user_id='u',field_name='email',old_value='old@example.com',new_value='fresh@example.com',event_time='2026-01-01T09:00:00Z'),dict(user_id='v',field_name='email',old_value='v@example.com',new_value='old@example.com',event_time='2026-01-01T09:30:00Z')]
            auditor.identity=IdentityResolver(rows,history);subject=auditor.identity.resolve('fresh@example.com','2026-01-02T00:00:00Z')
            auditor.store.by_resource['ours'][0].fields.pop('user_id')
            auditor.store.by_resource['ours'][0].identity_keys.discard('u')
            self.assertEqual(auditor._discover(subject,'2026-01-02T00:00:00Z'),set())

    def test_document_mention_is_not_state_and_future_embedded_time_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[dict(system='account_service',resource_id='r',record_type='USER_PROFILE',email='old@example.com')]);auditor=Auditor(root)
            base={'file_id':'doc','captured_at':'2026-01-01T12:00:00Z','kind':'ocr'}
            auditor.store.documents=[dict(base,text='Resource catalog: r')]
            self.assertEqual(auditor._document_reads({'r'},'2026-01-02T00:00:00Z',None)[0],[])
            auditor.store.documents=[dict(base,text='Observed at 2026-01-01T10:00:00Z\nRefer to r for the migration\nresource_id=other email=old@example.com')]
            self.assertEqual(auditor._document_reads({'r'},'2026-01-02T00:00:00Z',None)[0],[])
            auditor.store.documents=[dict(base,text='Observed at 2026-01-03T10:00:00Z\nresource_id=r email=old@example.com')]
            self.assertEqual(auditor._document_reads({'r'},'2026-01-02T00:00:00Z',None)[0],[])
            auditor.store.documents=[dict(base,text='Observed at 2026-01-01T10:00:00Z\nresource_id=r email=old@example.com')]
            reads=auditor._document_reads({'r'},'2026-01-02T00:00:00Z',None)[0]
            self.assertEqual(len(reads),1);self.assertEqual(reads[0].observed_at,'2026-01-01T10:00:00Z')

    def test_complete_cites_each_physical_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[dict(system='account_service',resource_id='r',record_type='USER_PROFILE',result='NOT_FOUND',subject_reference='old@example.com')]);auditor=Auditor(root)
            replica=Observation('replica','account_service','r','USER_PROFILE','ABSENT','2026-01-01T10:00:00Z','2026-01-01T12:00:00Z',{},set(),scope='replica')
            auditor.store.by_resource['r'].append(replica)
            decision=auditor.audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-02T00:00:00Z'),True)
            self.assertEqual(decision.status,'COMPLETE')
            self.assertEqual({s['evidence_id'] for s in decision.steps},{'e','replica'})

    def test_document_flow_needs_scoped_runtime_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[dict(system='integration_service',resource_id='flow_a',record_type='DATA_FLOW',enabled=True,subject_reference='u')]);auditor=Auditor(root)
            doc={'file_id':'doc','captured_at':'2026-01-01T12:00:00Z','kind':'ocr','text':'PRODUCTION 01 Jan 2026 10:00 UTC\nflow_a\nStatus Healthy\nSelector old@example.com\nSync mode Continuous sync\nLast response 200 OK\n124 events delivered'}
            auditor.store.documents=[doc]
            reads=auditor._document_reads({'flow_a'},'2026-01-02T00:00:00Z',None)[0]
            self.assertEqual(len(reads),1);self.assertEqual(reads[0].state,'ACTIVE')
            auditor.store.documents=[dict(doc,text='PRODUCTION 01 Jan 2026 10:00 UTC\nResource catalog flow_a\nOther connectors are Continuous sync')]
            self.assertEqual(auditor._document_reads({'flow_a'},'2026-01-02T00:00:00Z',None)[0],[])

    def test_expired_hold_is_disproved_not_missing_policy_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['LEGAL_HOLD_RECORD']={'condition':'A supplied legal hold is active','required_action':'RETAIN'}
            o=Observation('e','s','r','LEGAL_HOLD_RECORD','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{'legal_hold_active':True,'hold_until':'2026-01-01T01:00:00Z'})
            self.assertEqual(auditor._action(o.category,o,'2026-01-02T00:00:00Z'),'UNSPECIFIED_POLICY')

    def test_expired_security_retention_is_distinct_from_missing_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[]);auditor=Auditor(root)
            auditor.rules['SECURITY_AUDIT_LOG']={'condition':'Record is within the supplied retention period','required_action':'RETAIN'}
            observation=Observation('e','security_service','s','SECURITY_AUDIT_LOG','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',{'retention_until':'2026-01-01T01:00:00Z'})
            self.assertEqual(auditor._action('SECURITY_AUDIT_LOG',observation,'2026-01-02T00:00:00Z'),'UNSPECIFIED_POLICY')
            observation.fields={}
            self.assertIsNone(auditor._action('SECURITY_AUDIT_LOG',observation,'2026-01-02T00:00:00Z'))

    def test_false_support_predicate_without_fallback_cannot_prove_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='support_platform',resource_id='message_1',record_type='SUPPORT_MESSAGE',subject_reference='u',shared_context=False,message_text='Private message with customer details')])
            auditor=Auditor(root)
            auditor.rules['SUPPORT_MESSAGE']={'condition':'Conversation contains shared customer, agent, or order context that must be retained','required_action':'REDACT'}
            with self.assertRaises(UnresolvedAudit) as caught:
                auditor.audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-02T00:00:00Z'),True)
            self.assertIn('fallback treatment is not supplied',str(caught.exception.details))

    def test_expired_security_record_cannot_be_skipped_from_complete_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='security_service',resource_id='audit_r',record_type='SECURITY_AUDIT_LOG',subject_reference='u',retention_until='2026-01-01T01:00:00Z')])
            with self.assertRaises(UnresolvedAudit) as caught:
                Auditor(root).audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-02T00:00:00Z'),True)
            self.assertIn('fallback treatment is not supplied',str(caught.exception.details))

    def test_tombstone_cannot_use_email_as_stable_reference(self):
        fields=dict(subject_reference='old@example.com',account_status='DELETED',name=None,email=None,phone=None,email_hash=None)
        self.assertEqual(infer_state('ACCOUNT_TOMBSTONE',fields),'')

    def test_ocr_keeps_independent_sparse_text_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'evidence').mkdir()
            (root/'evidence/a.png').write_bytes(b'fake image: OCR subprocess is replaced')
            (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.png,source,2026-01-01T12:00:00Z\n')
            outputs=[SimpleNamespace(returncode=0,stdout='resource flow_a',stderr=''),SimpleNamespace(returncode=0,stdout='flow_a Selector old@example.com Sync mode Continuous sync Last response 200 OK',stderr='')]
            with patch('ghost_audit.ingest.shutil.which',return_value='tesseract'),patch('ghost_audit.ingest.subprocess.run',side_effect=outputs) as run:
                docs=Store(root).documents
            self.assertEqual(len(docs),2)
            self.assertEqual({d['file_id'] for d in docs},{'e'})
            self.assertIn('--psm',run.call_args_list[1].args[0])

    def test_json_snapshot_time_is_not_row_version_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[])
            (root/'evidence/a.json').write_text(json.dumps({'captured_at':'2026-01-01T10:00:00Z','service_exports':{'account_service':{'customer_profiles':[{'resource_id':'r','user_id':'u','updated_at':'2025-01-01T00:00:00Z'}]}}}))
            self.assertEqual(Store(root).observations[0].observed_at,'2026-01-01T10:00:00Z')

    def test_journal_retention_deadline_is_not_observation_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[dict(system='security_service',resource_id='audit_a',record_type='SECURITY_AUDIT_LOG',subject_reference='u')]);auditor=Auditor(root)
            auditor.store.documents=[{'file_id':'doc','kind':'pdf','captured_at':'2026-01-01T12:00:00Z','text':'Issued 01 Jan 2026 10\n00 UTC\nEvent reference audit_a\nSubject reference u\nIntegrity seal valid\nRetain until 01 Jan 2027 10\n00 UTC'}]
            reads=auditor._document_reads({'audit_a'},'2026-01-02T00:00:00Z',None)[0]
            self.assertEqual(len(reads),1);self.assertEqual(reads[0].state,'PRESENT')
            self.assertEqual(reads[0].fields['retention_until'],'2027-01-01T10:00:00+00:00')

    def test_catalog_descriptor_requires_visible_business_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.make_dataset(root,[], 'a,2026-01-01T11:00:00Z,LINK_RESOURCE_IDENTITY,object_storage,object_storage,obj_a,,Catalog confirmed obj_a (receipt.pdf) belongs only to old@example.com and u\n');auditor=Auditor(root)
            auditor.store.documents=[{'file_id':'doc','kind':'ocr','captured_at':'2026-01-01T12:00:00Z','text':'PRODUCTION 01 Jan 2026 10:00 UTC\nreceipt.pdf\nFile size 684 KB\nOwner old@example.com'}]
            reads=auditor._document_reads({'obj_a'},'2026-01-02T00:00:00Z',None)[0]
            self.assertEqual(len(reads),1);self.assertEqual(reads[0].state,'PRESENT')

    def make_dataset(self, root, records, activities=''):
        (root/'evidence').mkdir()
        (root/'user_identities.csv').write_text('user_id,email,name,phone,email_hash,updated_at\nu,old@example.com,Person,,,2026-01-01T00:00:00Z\n')
        (root/'deletion_rules.csv').write_text('rule_id,data_category,condition,required_action\np,USER_PROFILE,Always,DELETE\na,ANALYTICS_PROFILE,Attributable,ANONYMIZE\ns,SECURITY_AUDIT_LOG,Retention,RETAIN\n')
        (root/'system_activity.csv').write_text('activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n'+activities)
        (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.json,source,2026-01-01T12:00:00Z\n')
        (root/'evidence/a.json').write_text(json.dumps({'exported_at':'2026-01-01T10:00:00Z','records':records}))

    def test_engine_claim_cannot_override_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='account_service',resource_id='r',record_type='USER_PROFILE',result='FOUND',subject_reference='old@example.com')], 'a,2026-01-01T11:00:00Z,DELETE_RECORD,deletion_worker,account_service,r,SUCCESS,Deletion complete\n')
            decision=Auditor(root).audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-01T13:00:00Z'),True)
            self.assertEqual(decision.status,'INCOMPLETE')
            self.assertEqual([s['operation'] for s in decision.steps],['REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT'])
            self.assertEqual(Auditor(root).audit(dict(case_id='n'),False).steps,[])

    def test_engine_unresolved_retained_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='security_service',resource_id='r',record_type='SECURITY_AUDIT_LOG',result='NOT_FOUND',subject_reference='old@example.com')])
            with self.assertRaises(UnresolvedAudit):
                Auditor(root).audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-01T13:00:00Z'),True)

    def test_contract_order_and_future_citation(self):
        steps = compile_steps([dict(phase='VERIFICATION', system_id='s', resource_id='r', operation='VERIFY_RECORD_ABSENT', state='ABSENT', evidence_id='e')])
        row = dict(case_id='c', deletion_status='COMPLETE', steps_json=json.dumps(steps))
        validate_row(row)
        with self.assertRaises(ValueError):
            validate_row(row, {'e': '2026-02-01T00:00:00Z'}, '2026-01-01T00:00:00Z')

    def test_explicit_scan_fields_and_redacted_body(self):
        self.assertEqual(infer_state('SUPPORT_MESSAGE',{'message_text':'[REDACTED]','subject_reference':'u'}),'REDACTED')
        self.assertEqual(infer_state('SUPPORT_MESSAGE',{'matched_value':'old@example.com','detector':'direct_identifier'}),'PRESENT')
        self.assertEqual(infer_state('ANALYTICS_PROFILE',{'direct_identifiers':'1','matched_value':'old@example.com'}),'PRESENT')

    def test_query_identifier_links_search_but_is_not_pii_state(self):
        fields={'query':'old@example.com','hits':{'total':0,'documents':[]}}
        self.assertIn('old@example.com',keys_from(fields))
        self.assertEqual(infer_state('SEARCH_INDEX_ENTRY',fields),'ABSENT')

    def test_backup_preserves_archive_and_blocks_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.make_dataset(root,[dict(system='backup_service',resource_id='r',record_type='BACKUP_ARCHIVE',result='BLOCKED',subject_reference='old@example.com')])
            with (root/'deletion_rules.csv').open('a') as f:f.write('b,BACKUP_ARCHIVE,Block restore,RETAIN\n')
            decision=Auditor(root).audit(dict(case_id='c',email='old@example.com',audit_at='2026-01-01T13:00:00Z'),True)
            self.assertEqual([s['operation'] for s in decision.steps],['VERIFY_RECORD_PRESENT','VERIFY_RESTORE_BLOCKED'])

    def test_capture_gate_and_physical_replicas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'evidence').mkdir()
            (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/data.sql,source,2026-02-01T00:00:00Z\n')
            (root/'evidence/data.sql').write_text("CREATE TABLE customer_data_primary(resource_id,origin_system,collection_name,record_json,updated_at); CREATE TABLE customer_data_read_replica(resource_id,origin_system,collection_name,record_json,updated_at); INSERT INTO customer_data_read_replica VALUES('r','account_service','customer_profiles','{\"email\":\"x@y.com\"}','2026-01-01T00:00:00Z');")
            store = Store(root)
            self.assertEqual(len(store.observations), 1)
            self.assertEqual(store.observations[0].scope, 'customer_data_read_replica')
            self.assertEqual(store.observations[0].observed_at,'2026-02-01T00:00:00Z')
            self.assertFalse(store.observations[0].eligible('2026-01-15T00:00:00Z'))

    def test_temporal_identity_recycled_email(self):
        rows = [dict(user_id='u',email='new@example.com',phone='',email_hash='',name='N',updated_at='2026-03-01T00:00:00Z')]
        history = [dict(user_id='u',field_name='email',old_value='old@example.com',new_value='new@example.com',event_time='2026-02-01T00:00:00Z')]
        resolver = IdentityResolver(rows, history)
        subject = resolver.resolve('OLD@example.com', '2026-01-01T00:00:00Z')
        self.assertEqual(subject.user_id, 'u')
        self.assertIn('old@example.com', subject.aliases)
        self.assertNotIn('new@example.com', subject.aliases)

    def test_trace_join_does_not_accept_cache_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'evidence').mkdir()
            (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.log,source,2026-01-01T12:00:00Z\n')
            (root/'evidence/a.log').write_text('2026-01-01T10:00:00Z service=account_service instance=a trace_id=t event=profile_lookup_started lookup_key=old@example.com\n2026-01-01T10:00:01Z service=account_service instance=a trace_id=t event=cache_miss\n2026-01-01T10:00:02Z service=account_service instance=a trace_id=t event=profile_lookup_completed resource_id=r rows=0 http_status=404\n')
            store=Store(root)
            self.assertEqual(len(store.observations),1)
            self.assertEqual(store.observations[0].state,'ABSENT')
            self.assertIn('old@example.com',store.observations[0].identity_keys)

    def test_log_lookup_uses_declared_business_system_and_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'evidence').mkdir()
            (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.log,source,2026-01-01T12:00:00Z\n')
            (root/'evidence/a.log').write_text('2026-01-01T10:00:00Z service=collector event=record_lookup system="account_service" resource_id="r" record_type="USER_PROFILE" result="NOT_FOUND" subject_reference="old@example.com"\n')
            o=Store(root).observations[0]
            self.assertEqual((o.system_id,o.category,o.state),('account_service','USER_PROFILE','ABSENT'))

    def test_started_read_is_not_a_state_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'evidence').mkdir()
            (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.log,source,2026-01-01T12:00:00Z\n')
            (root/'evidence/a.log').write_text('2026-01-01T10:00:00Z service=analytics_platform trace_id=t event=analytics_profile_read_started resource_id=r lookup_key=old@example.com\n2026-01-01T10:00:00Z service=analytics_platform trace_id=t event=analytics_profile_read_completed resource_id=r email=null phone=null email_hash=null customer_reference=null\n')
            observations=Store(root).observations
            self.assertEqual(len(observations),1)
            self.assertEqual(observations[0].state,'ANONYMIZED')

    def test_six_log_envelopes_preserve_service(self):
        payload='instance="a" resource_id="r" event="profile_lookup_completed" rows="1" correlation_key="old@example.com"'
        lines=[
            'service=account_service trace_id=t '+payload,
            json.dumps(dict(service='account_service',instance='a',trace_id='t',event='profile_lookup_completed',resource_id='r',rows='1',correlation_key='old@example.com')),
            '[INFO] [account_service] [t] profile_lookup_completed: '+payload,
            '| INFO | account_service | t | profile_lookup_completed | '+payload,
            '<14>1 node account_service t - - '+payload,
            'requestId=t function=account_service message='+json.dumps(payload),
        ]
        for envelope in lines:
            with self.subTest(envelope=envelope),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'evidence').mkdir()
                (root/'evidence_files.csv').write_text('file_id,file_path,origin,captured_at\ne,evidence/a.log,source,2026-01-01T12:00:00Z\n')
                (root/'evidence/a.log').write_text('2026-01-01T10:00:00Z '+envelope+'\n')
                observations=Store(root).observations
                self.assertEqual(len(observations),1)
                self.assertEqual((observations[0].system_id,observations[0].state),('account_service','PRESENT'))


if __name__ == '__main__':
    unittest.main()
