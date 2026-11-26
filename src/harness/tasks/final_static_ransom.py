"""Late static supplement: invoked only after advisory review, before adjudication."""
import json
from pathlib import Path
from harness.static.ransom_information import scan_ransom_information,static_claims
from .models import SessionFact,TaskResult

TASK='final_static_ransom_evidence'

def collect_final_static(context,claims,observations):
 if 'static_sample' not in context.state.artifacts:return claims,observations,{'status':'not_supplied','items':[]}
 report=None
 existing=context.state.task_results.get(TASK)
 if existing:
  report=json.loads(Path(existing.artifacts['static_ransom_information'].path).read_text())
 else:
  path=Path(context.state.artifact('static_sample').path)
  try:
   report=scan_ransom_information(path);report['extraction_status']='completed'
  except (OSError,ValueError) as exc:
   report={'schema_version':'harness-static-ransom-information-v035','contents':[],
      'extraction_status':'unavailable','error_type':type(exc).__name__,
      'coverage':'Extraction failed or exceeded its bound; not evidence of absence.'}
  raw=static_claims(report);memory={'facts':[]}
  for i,c in enumerate(raw,1):
   memory['facts'].append({'fact_id':f'static_ransom_fact_{i:06d}','source_tool':'static_ransom_information',
       'query':{'scope':'supplied executable'},'summary':'Ransom content extracted after independent review',
       'evidence_ref_ids':c['evidence_ref_ids'],'block_ids':[],'event_offsets':[],
       'aggregate_digest':c['static_ransom_information'],'event_examples':[],'block_examples':[],
       'limitations':c['uncertainty']})
  artifacts={}
  for name,value in [('static_ransom_information',report),('candidate_claims',raw),('local_memory',memory)]:
   p=context.store.path_for(TASK,name+'.json');p.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
   artifacts[name]=context.store.artifact_ref(TASK,name,name,p,{'stage':'final_adjudication_only'})
  facts=tuple(SessionFact(fact_id=f'{TASK}:claim:{c["claim_id"]}',kind='candidate_claim',data=c,source_task_id=TASK,
                  artifact_ids=(artifacts['candidate_claims'].artifact_id,)) for c in raw)
  context.state.commit(TaskResult.completed(TASK,artifacts=artifacts,facts=facts,
       diagnostics={'extraction_status':report['extraction_status'],'model_requests':0,'stage':'after_independent_review'}))
 result=list(claims);obs=list(observations)
 raw=json.loads(Path(context.state.task_results[TASK].artifacts['candidate_claims'].path).read_text())
 for c in raw:
  keys=['claim_id','agent_id','claim_type','statement','evidence_ref_ids','supporting_block_ids','alternative_explanations','uncertainty','static_ransom_information']
  value={k:c[k] for k in keys if k in c};value.update(claim_id=TASK+':'+c['claim_id'],original_claim_id=c['claim_id'],source=TASK,evidence_kind='static')
  result.append(value)
 memory=json.loads(Path(context.state.task_results[TASK].artifacts['local_memory'].path).read_text())
 obs.extend({'source_task_id':TASK,**f} for f in memory['facts'])
 return result,obs,{'status':report['extraction_status'],'content_count':len(report['contents']),
     'not_seen_by':['investigators','initial_assessment','independent_reviewer'],
     'instruction':'This supplement was obtained after the independent review. That review did not assess it. Evaluate its provenance and relation to dynamic evidence explicitly.'}
