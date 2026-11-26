"""Build local evidence from a single sample and run the retained analysis tasks."""
from importlib.resources import files
from pathlib import Path
import hashlib
import json
import math
import os
import time

from harness.behavior.catalog import build_behavior_catalog
from harness.behavior_snapshot import BehaviorSnapshotSample
from harness.snapshot_pipeline import run_analysis_pipeline_from_behavior_snapshot
from .sample import SampleDirectory, SampleError, FILES

class AnalysisError(ValueError):
    """Public configuration or runtime error without embedded credentials."""

def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(8*1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def resource(name):
    return json.loads(files('ransift').joinpath('resources',name).read_text(encoding='utf-8'))

def load_client(config_path):
    """Load only an explicit config and named environment credential."""
    from harness.behavior.llm_loop import OpenAICompatibleConfig, OpenAISDKCompatibleChatClient
    try:
        data=json.loads(Path(config_path).read_text(encoding='utf-8'))
        if not isinstance(data,dict) or 'api_key' in data:
            raise AnalysisError('Use api_key_env; literal API keys are not accepted in the configuration.')
        model=data.get('model');url=data.get('base_url');env=data.get('api_key_env','RANSIFT_API_KEY')
        if not isinstance(model,str) or not model.strip() or model=='YOUR_MODEL_ID':
            raise AnalysisError('Set an explicit model ID.')
        if not isinstance(url,str) or not url.startswith(('https://','http://')) or '.invalid' in url:
            raise AnalysisError('Set an explicit API base URL.')
        from urllib.parse import urlsplit
        parsed=urlsplit(url)
        if not parsed.hostname:
            raise AnalysisError('API base URL must include a hostname.')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise AnalysisError('API base URL must not contain embedded credentials, query or fragment.')
        if not isinstance(env,str) or not env or not os.environ.get(env):
            raise AnalysisError('The configured API credential environment variable is not set.')
        timeout=float(data.get('timeout_seconds',240))
        temperature=float(data.get('temperature',0))
        cap=data.get('max_tokens')
        if not math.isfinite(timeout) or timeout<=0 or not math.isfinite(temperature) or not 0<=temperature<=2 or (cap is not None and (type(cap) is not int or cap<=0)):
            raise AnalysisError('Invalid model parameters.')
        config=OpenAICompatibleConfig(model=model.strip(),base_url=url,api_key=os.environ[env],
            timeout_seconds=timeout,temperature=temperature,max_tokens=cap,parse_retries=1)
        return OpenAISDKCompatibleChatClient(config,trust_env=False)
    except AnalysisError:
        raise
    except (OSError,ValueError,TypeError,ImportError,RuntimeError):
        raise AnalysisError('Unable to load the explicit model configuration or client dependencies.') from None

class RecordedClient:
    """Record time and returned usage, never authentication headers/configuration."""
    def __init__(self,client,path):
        self.client=client;self.path=Path(path);self.calls=[]
    def complete_json(self,messages):return self._call(messages,False)
    def complete_json_once(self,messages):return self._call(messages,True)
    def _call(self,messages,once):
        p=json.loads(messages[-1]['content']);start=time.monotonic()
        row={'sequence':len(self.calls)+1,'phase':p.get('structured_output',{}).get('stage'),
             'agent_id':p.get('agent_prompt',{}).get('agent_id')}
        try:
            fn=getattr(self.client,'complete_json_once',self.client.complete_json) if once else self.client.complete_json
            result=fn(messages)
            row.update(status='success',usage=result.get('_usage'))
            return result
        except Exception as exc:
            row.update(status='error',error_type=type(exc).__name__,usage=None)
            raise
        finally:
            row['elapsed_seconds']=time.monotonic()-start;self.calls.append(row)
            with self.path.open('a',encoding='utf-8') as f:f.write(json.dumps(row)+'\n')

def analyze(sample_dir,output,*,client=None,config_path=None,static_sample=None,prepare_only=False):
    sample=SampleDirectory.open(sample_dir)
    target=Path(output).absolute()
    if target.resolve()!=target or target==sample.root or sample.root in target.parents or target in sample.root.parents:
        raise AnalysisError('Output must be a new canonical directory separate from the sample directory.')
    if target.exists():raise AnalysisError('Output already exists; use a new output directory.')
    if prepare_only and (client is not None or config_path is not None or static_sample is not None):
        raise AnalysisError('Preparation-only mode does not accept a model client/config or static binary.')
    if not prepare_only and client is None and config_path is None:
        raise AnalysisError('Analysis requires an explicit model configuration.')
    static=None
    if static_sample is not None:
        static=Path(static_sample).absolute()
        if static.is_symlink() or not static.is_file():
            raise AnalysisError('Optional static input must be an explicitly supplied regular file.')
    # Validate before constructing a client or writing any output.
    validation=sample.validate(full=True)
    model=client if client is not None else (None if prepare_only else load_client(config_path))
    target.mkdir(parents=True,exist_ok=False)
    start=time.monotonic();prepared=target/'prepared';prepared.mkdir()
    digests={name:sha256(sample.root/name) for name in FILES}
    sample_id='sample-'+digests['normalized_events.jsonl'][:16]
    catalog=build_behavior_catalog(trace_path=sample.root/'normalized_events.jsonl',
        phase_blocks_path=prepared/'phase_blocks.jsonl',checkpoints_path=prepared/'checkpoints.json')
    write_json(prepared/'catalog.json',catalog)
    summary={'schema_version':'harness-behavior-trace-summary-v1','event_count':catalog['event_count'],
        'time_inversions':catalog['trace_time_inversions'],'node_count':len(json.loads((sample.root/'process_tree.json').read_text(encoding='utf-8-sig'))['node_index'])}
    write_json(prepared/'trace_summary.json',summary)
    provenance={'schema_version':'ransift-sample-input-v1','sample_id':sample_id,'files':digests,
                'validation':validation,'static_input':'provided' if static is not None else 'not_supplied'}
    write_json(target/'input.json',provenance)
    prepared_seconds=time.monotonic()-start
    if prepare_only:
        result={'status':'prepared','sample_id':sample_id,'event_count':catalog['event_count'],
                'preparation_seconds':prepared_seconds,'model_requests':0}
        write_json(target/'result.json',result);return result
    for name in ['default.json','output_layout.json']:write_json(prepared/name,resource(name))
    record={'artifacts':{'catalog_sha256':sha256(prepared/'catalog.json'),
              'phase_blocks_sha256':sha256(prepared/'phase_blocks.jsonl'),
              'checkpoints_sha256':sha256(prepared/'checkpoints.json')},
            'upstream':{'trace_sha256':digests['normalized_events.jsonl']}}
    # Register the supplied trace and locally constructed evidence artifacts.
    snapshot=BehaviorSnapshotSample(snapshot_root=prepared,snapshot_id='local-evidence-v1',
        snapshot_metadata_sha256=sha256(target/'input.json'),snapshot_manifest_sha256=sha256(target/'input.json'),
        sample_key=sample_id,trace_snapshot_root=sample.root,trace_snapshot_id='sample-directory-v1',
        trace_metadata_sha256=sha256(target/'input.json'),trace_manifest_sha256=sha256(target/'input.json'),
        trace_path=sample.root/'normalized_events.jsonl',trace_summary_path=prepared/'trace_summary.json',
        catalog_path=prepared/'catalog.json',phase_blocks_path=prepared/'phase_blocks.jsonl',
        checkpoints_path=prepared/'checkpoints.json',trace_summary=summary,catalog=catalog,manifest_record=record)
    recorded=RecordedClient(model,target/'api-calls.jsonl');run_start=time.monotonic()
    try:
        session=run_analysis_pipeline_from_behavior_snapshot(raw_log_path=sample.root/'raw_events.csv',
            sample_id=sample_id,behavior_snapshot_path='',behavior_sample_key=sample_id,prepared_snapshot=snapshot,
            harness_root=target,layout_config_path=prepared/'output_layout.json',role_profile_path=prepared/'default.json',
            static_sample_path=static,client=recorded,run_verdict=True,
            input_metadata={'input_interface':'three-file-sample-directory'})
        ref=session.state.artifacts.get('finalize_sample_decision:sample_decision')
        decision=json.loads(Path(ref.path).read_text()) if ref else {}
        verdict=decision.get('verdict')
        result={'status':'completed' if verdict in ('malicious','benign') else 'failed',
                'verdict':verdict if verdict in ('malicious','benign') else None,
                'decision_status':decision.get('status'),'sample_id':sample_id,
                'decision':str(Path(ref.path).relative_to(target)) if ref else None}
    except Exception as exc:
        result={'status':'failed','verdict':None,'sample_id':sample_id,'error_type':type(exc).__name__}
    result.update(preparation_seconds=prepared_seconds,analysis_seconds=time.monotonic()-run_start,
        model_requests=len(recorded.calls),successful_requests=sum(x['status']=='success' for x in recorded.calls),
        failed_requests=sum(x['status']=='error' for x in recorded.calls),
        input_tokens=sum((x.get('usage') or {}).get('prompt_tokens',0) or 0 for x in recorded.calls),
        output_tokens=sum((x.get('usage') or {}).get('completion_tokens',0) or 0 for x in recorded.calls),
        successful_requests_without_usage=sum(x['status']=='success' and not x.get('usage') for x in recorded.calls))
    result['total_tokens']=result['input_tokens']+result['output_tokens']
    write_json(target/'result.json',result)
    return result
