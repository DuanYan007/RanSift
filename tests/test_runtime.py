"""Exercise the public adapter and real task machinery with a local SDK stub."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import csv
import json
import tempfile
import unittest

from harness.behavior.llm_loop import OpenAICompatibleConfig, OpenAISDKCompatibleChatClient
from harness.structured_output import validate_output
from ransift.runtime import analyze, AnalysisError, load_client
from ransift.sample import CSV_FIELDS


def make_sample(root):
    root.mkdir()
    with (root/'raw_events.csv').open('w',newline='') as f:
        writer=csv.writer(f);writer.writerow(CSV_FIELDS)
        writer.writerow(['00:00:01','demo.exe',42,'WriteFile','C:\\Demo\\output.txt','SUCCESS','Offset: 0, Length: 4'])
    tree={'root_nodes':['node_1'],'node_index':{'node_1':{'process':{'pid':42,'name':'demo.exe'}}}}
    (root/'process_tree.json').write_text(json.dumps(tree))
    event={'order':{'filtered':0,'source':'ev_00000000','source_numeric':0},
        'time':{'timestamp':1.0,'raw_time':'00:00:01'},
        'action':{'operation':'WriteFile','category':'file','result':'SUCCESS','operation_family':'file_write'},
        'target':{'path':'C:\\Demo\\output.txt','normalized_path':'c:\\demo\\output.txt','namespace':'other','extension':'txt'},
        'detail':{'raw_detail':'Offset: 0, Length: 4','parsed':{}},
        'process_context':{'pid':42,'process_name':'demo.exe','node_id':'node_1','depth':0,'process_key':'node_1|42|demo.exe'}}
    (root/'normalized_events.jsonl').write_text(json.dumps(event)+'\n')

class OfflineSDK(OpenAISDKCompatibleChatClient):
    """Mock transport responses only; real strict decoding and E/C/Q resolution run."""
    def __init__(self,fail=False,label='benign'):
        self.config=OpenAICompatibleConfig(model='offline-test',parse_retries=1)
        self.client=SimpleNamespace(with_options=lambda **kw:self.client)
        self.calls=[];self.fail=fail;self.label=label;self.queried=False
    def _create_completion(self,client,kwargs):
        self.calls.append(deepcopy(kwargs))
        if self.fail:raise ConnectionError('Synthetic transport failure')
        p=json.loads(kwargs['messages'][-1]['content']);stage=p['structured_output']['stage']
        assert kwargs['response_format']['json_schema']['strict'] is True
        assert kwargs['response_format']['json_schema']['schema']==p['output_schema']
        if stage=='investigation':
            role=p['agent_prompt']['agent_id'];w=p['working_context']
            if role=='process' and not self.queried and 'tool_request' in p['structured_output']['allowed_actions']:
                self.queried=True
                body={'tool_request':{'tool_name':'search_events','arguments':{'patterns':['WriteFile'],
                      'fields':['operation'],'limit':5,'cursor':None},'purpose':'Inspect synthetic operation.'}}
            else:
                if role=='file_transformation':
                    refs=next(f['support_ids'] for f in w['facts'] if f.get('support_ids'))
                    claim={'claim_type':'file_transformation_behavior','statement':'The demo process wrote an output file.',
                        'observed_operations':['WriteFile'],'behavior_interpretation':'Recorded file output; contents unobserved.',
                        'support_ids':refs[:1],'alternative_explanations':['Ordinary application output.'],
                        'uncertainty':['Contents not observed.']}
                    body={'claim_output':{'claims':[claim]}}
                else:
                    body={'no_evidence':{'support_ids':w['visible_query_ids'],
                        'scope':'No role-relevant finding in the synthetic observations.','uncertainty':[]}}
                body['investigation_closure']={'leads':[{'lead_id':lead['lead_id'],'status':'not_relevant',
                    'explanation':'This synthetic input adds no further role-relevant target.',
                    'support_ids':lead['support_ids'],'next_step':''} for lead in w['followup_leads']], 'limitations':[]}
            wire={'response':body}
        else:
            cid=p['claims'][0]['claim_id']
            if stage=='review':
                wire={'verdict_assessment':'supported','summary':'Synthetic review of recorded file output.',
                    'issues':[{'description':'Keep the content limitation.','impact':'report_only','support_ids':[cid]}]}
            else:
                wire={'verdict':self.label,'risk_summary':'Synthetic transport response for integration testing.',
                    'reasoning':[{'role':'support','explanation':'Ordinary output explains the recorded write.','support_ids':[cid]}],
                    'attack_story':[{'phase':'file output','action':'An output file was written.','support_ids':[cid]}],
                    'benign_alternatives':['Ordinary application output.'],'uncertainties':['Contents unobserved.'],
                    'analysis_status':'complete','analysis_gaps':[]}
                if stage=='final':wire['review_resolution']=[{'issue_index':0,'resolution':'Content limitation retained.','support_ids':[cid]}]
            wire['claim_connections']=[]
            wire['hypothesis_assessment']={label:{'support_ids':[cid],'counter_ids':[],
                'explanation':'Synthetic comparison of explanations.','unconfirmed_assumptions':[]} for label in ['malicious','benign']}
        validate_output(wire,p['output_schema'])
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(wire),refusal=None),finish_reason='stop')],
            usage=SimpleNamespace(prompt_tokens=10,completion_tokens=5))

class RuntimeTests(unittest.TestCase):
    def test_full_pipeline_read_only_no_network_no_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sample=root/'input';make_sample(sample)
            before={p.name:p.read_bytes() for p in sample.iterdir()};client=OfflineSDK()
            with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
                result=analyze(sample,root/'output',client=client)
            self.assertEqual(result['status'],'completed',result)
            self.assertEqual(result['verdict'],'benign',result)
            self.assertEqual(before,{p.name:p.read_bytes() for p in sample.iterdir()})
            stages=[json.loads(c['messages'][-1]['content'])['structured_output']['stage'] for c in client.calls]
            self.assertTrue({'investigation','assessment','review','final'}<=set(stages),stages)
            roles={json.loads(c['messages'][-1]['content']).get('agent_prompt',{}).get('agent_id') for c in client.calls}
            self.assertTrue({'process','file_discovery','file_transformation','registry','recovery','ransom_note','anti_analysis'}<=roles)
            self.assertTrue(client.queried)
            self.assertEqual(result['input_tokens'],10*len(client.calls))
            self.assertEqual(result['total_tokens'],15*len(client.calls))
            for c in client.calls:
                self.assertNotIn(str(root),json.dumps(c['messages']))

    def test_optional_static_is_local_and_final_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);make_sample(root/'input')
            # Plain synthetic text, never an executable or a downloaded sample.
            supplied=root/'synthetic-content.txt'
            supplied.write_text('Your files are encrypted. Pay bitcoin to decrypt your files.')
            client=OfflineSDK()
            with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
                result=analyze(root/'input',root/'out',client=client,static_sample=supplied)
            self.assertEqual(result['status'],'completed',result)
            final_static=False
            for call in client.calls:
                p=json.loads(call['messages'][-1]['content']);stage=p['structured_output']['stage']
                static_claims=[c for c in p.get('claims',[]) if c.get('evidence_kind')=='static']
                if stage!='final':self.assertFalse(static_claims)
                else:final_static=bool(static_claims)
            self.assertTrue(final_static)

    def test_failure_stays_unlabeled(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);make_sample(r/'input')
            with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
                result=analyze(r/'input',r/'output',client=OfflineSDK(fail=True))
            self.assertEqual(result['status'],'failed');self.assertIsNone(result['verdict'])
            self.assertGreater(result['failed_requests'],0)

    def test_prepare_only_does_not_construct_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);make_sample(r/'input')
            with patch('ransift.runtime.load_client',side_effect=AssertionError('Model forbidden')):
                result=analyze(r/'input',r/'out',prepare_only=True)
            self.assertEqual(result['status'],'prepared');self.assertEqual(result['model_requests'],0)

    def test_output_cannot_be_inside_sample_or_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);make_sample(r/'input')
            for out in [r/'input',r/'input'/'new',r]:
                with self.assertRaises(AnalysisError):analyze(r/'input',out,prepare_only=True)
            analyze(r/'input',r/'out',prepare_only=True)
            with self.assertRaises(AnalysisError):analyze(r/'input',r/'out',prepare_only=True)

    def test_no_implicit_model_config_or_literal_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp);make_sample(r/'input')
            with self.assertRaises(AnalysisError):analyze(r/'input',r/'out')
            config=r/'client.json';config.write_text(json.dumps({'api_key':'synthetic-disallowed-value'}))
            with self.assertRaises(AnalysisError):load_client(config)
            self.assertFalse((r/'out').exists())

    def test_invalid_model_parameters_rejected_before_client_creation(self):
        for overrides in [{'timeout_seconds':float('nan')}, {'timeout_seconds':float('inf')},
                          {'temperature':float('nan')}, {'base_url':'https://'},
                          {'base_url':'https://example.invalid/v1?token=synthetic'}]:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as tmp:
                config=Path(tmp)/'model.json'
                config.write_text(json.dumps({'model':'test-model','base_url':'https://example.com/v1',
                    'api_key_env':'RANSIFT_TEST_KEY',**overrides}))
                with patch.dict('os.environ', {'RANSIFT_TEST_KEY':'synthetic-test-value'}), \
                     patch('harness.behavior.llm_loop.OpenAISDKCompatibleChatClient',
                           side_effect=AssertionError('Invalid config must not construct a client')):
                    with self.assertRaises(AnalysisError):load_client(config)

    def test_invalid_input_fails_before_output_or_model_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);make_sample(root/'input')
            event=json.loads((root/'input'/'normalized_events.jsonl').read_text())
            event['time']={}
            (root/'input'/'normalized_events.jsonl').write_text(json.dumps(event)+'\n')
            with patch('ransift.runtime.load_client',side_effect=AssertionError('Model forbidden')):
                from ransift.sample import SampleError
                with self.assertRaises(SampleError):
                    analyze(root/'input',root/'output',config_path=root/'unused.json')
            self.assertFalse((root/'output').exists())

if __name__=='__main__':unittest.main()
