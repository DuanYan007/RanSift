"""Per-session model reference views, with lossless canonical audit mappings.

E identifies returned evidence, C a validated finding, Q a query result.
Aliases are presentation handles, not evidence or behavioral decision rules.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import threading
import time

from harness.structured_output import bounded_ids, enum, ref_array, validate_output

VERSION = 'ransift-unified-references-v033'


def noncitable_context(value):
    """Keep contextual descriptions without advertising bookkeeping as evidence."""
    if isinstance(value,list):return [noncitable_context(item) for item in value]
    if not isinstance(value,dict):return deepcopy(value)
    administrative={'fact_id','fact_ids','artifact_id','artifact_ids','claim_id','claim_ids',
                    'evidence_ref_ids','supporting_claim_ids','supporting_block_ids',
                    'supporting_fact_ids','coverage_id','coverage_ids','original_claim_id','event_ref_id'}
    return {key:noncitable_context(item) for key,item in value.items() if key not in administrative}


class ReferenceCatalog:
    def __init__(self):
        self.forward, self.reverse = {}, {}
        self.claims = {}
        self.role_evidence = {}
        self.lock = threading.RLock()

    def register(self, kind, canonical):
        key = (kind,canonical)
        with self.lock:
            if key not in self.forward:
                count = sum(k[0]==kind for k in self.forward)+1
                alias = ('lead_' if kind=='lead' else kind)+f'{count:03d}'
                self.forward[key] = alias
                self.reverse[alias] = key
            return self.forward[key]

    def resolve(self, alias, kind, allowed):
        if not isinstance(alias,str) or alias not in allowed:
            raise ValueError('Reference was not supplied to this call: '+str(alias))
        actual,canonical = self.reverse[alias]
        if actual != kind:
            raise ValueError('Wrong reference kind: '+alias)
        return canonical

    def claim(self, item, scope):
        raw = item['claim_id']
        canonical = raw if ':' in raw else scope+':'+raw
        refs = tuple(dict.fromkeys(item.get('evidence_ref_ids',[])))
        if canonical in self.claims and set(self.claims[canonical]) != set(refs):
            raise ValueError('Claim evidence changed within one session: '+canonical)
        self.claims[canonical] = refs
        return self.register('C',canonical)

    def snapshot(self):
        return {'version':VERSION,'references':[{'id':alias,'kind':kind,'canonical':canonical}
                for alias,(kind,canonical) in self.reverse.items()],
                'claim_evidence':{cid:list(refs) for cid,refs in self.claims.items()},
                'role_evidence':{role:sorted(refs) for role,refs in self.role_evidence.items()}}


class ReferenceView:
    def __init__(self, catalog, payload):
        self.catalog = catalog
        self.original = deepcopy(payload)
        self.stage = payload['structured_output']['stage']
        self.scope = 'evidence_'+payload['agent_prompt']['agent_id'] if self.stage=='investigation' else ''
        self.allowed = {kind:set() for kind in ['E','C','Q','lead']}
        self.visible_queries = set()
        self.gap_queries = set()
        self.block_locators = set()
        self.coverage_ids = set(payload.get('analysis_coverage',{}).get('coverage_ids',[]))
        self._register(payload)

    def alias(self, kind, raw, scope=None):
        if kind in {'Q','lead'}:
            raw = raw if ':' in raw and raw.startswith('evidence_') else (scope or self.scope)+':'+raw
        alias = self.catalog.register(kind,raw)
        self.allowed[kind].add(alias)
        return alias

    def _register(self, p):
        w = p.get('working_context',{})
        facts = w.get('facts',[]) if self.scope else p.get('source_observations',[])
        for fact in facts:
            scope = fact.get('source_task_id',self.scope)
            query=self.alias('Q',fact['fact_id'],scope)
            if not self.scope:self.gap_queries.add(query)
            for raw in fact.get('evidence_ref_ids',[]):
                if not raw.startswith(('event:','block:')):continue
                alias = self.alias('E',raw)
                self.catalog.role_evidence.setdefault(scope,set()).add(alias)
        if self.scope:
            self.allowed['E'].update(self.catalog.role_evidence.get(self.scope,set()))
            for raw in w.get('investigation_fact_ids',[]): self.alias('Q',raw)
            for raw in w.get('visible_fact_ids',[]): self.visible_queries.add(self.alias('Q',raw))
            for lead in w.get('followup_leads',[]): self.alias('lead',lead['lead_id'])
        else:
            # Completed role reports can reference earlier query results which
            # have left recent memory. They must already exist in this session.
            self.allowed['Q'].update(alias for alias,(kind,_) in self.catalog.reverse.items() if kind=='Q')
        for item in p.get('claims',[]):
            self.allowed['C'].add(self.catalog.claim(item,item.get('source','')))
            for raw in item.get('evidence_ref_ids',[]): self.alias('E',raw)
        for item in w.get('claim_ledger',{}).get('claims',[]):
            self.allowed['C'].add(self.catalog.claim(item,self.scope))

    def _ids(self, values, kind, scope):
        result=[]
        for raw in values:
            canonical=raw
            if kind=='Q' and not (':' in raw and raw.startswith('evidence_')):
                canonical=(scope or self.scope)+':'+raw
            if kind=='C' and ':' not in raw:canonical=(scope or self.scope)+':'+raw
            alias=self.catalog.forward.get((kind,canonical))
            if alias not in self.allowed[kind]:
                raise ValueError('Input reference is outside the current call domain: '+str(raw))
            result.append(alias)
        return result

    def error_view(self,value,scope):
        if isinstance(value,list):return [self.error_view(item,scope) for item in value]
        if not isinstance(value,str):return deepcopy(value)
        replacements={canonical:alias for alias,(kind,canonical) in self.catalog.reverse.items()}
        for alias,(kind,canonical) in self.catalog.reverse.items():
            if kind in {'Q','lead'} and scope and canonical.startswith(scope+':'):
                replacements[canonical[len(scope)+1:]]=alias
        for raw in sorted(replacements,key=len,reverse=True):
            value=re.sub(r'(?<![\w:])'+re.escape(raw)+r'(?![\w:])',lambda _:replacements[raw],value)
        return value

    def project(self, value, scope=None):
        """Rewrite reference fields only; preserve observed strings verbatim."""
        scope = scope or self.scope
        if isinstance(value,list): return [self.project(item,scope) for item in value]
        if not isinstance(value,dict): return deepcopy(value)
        scope = value.get('source_task_id',scope)
        if isinstance(value.get('task_id'),str) and value['task_id'].startswith('evidence_'):
            scope=value['task_id']
        result = {}
        is_claim = 'claim_id' in value and ('evidence_ref_ids' in value or 'original_claim_id' in value)
        for key,item in value.items():
            if key in {'output_schema','reference_contract','structured_output','instruction'}: continue
            if key in {'supporting_block_ids','original_claim_id','artifact_id','artifact_ids','source_artifact_ids','coverage_id','coverage_ids'}: continue
            if key=='session_context':result[key]=noncitable_context(item)
            elif key in {'error','errors','original_error','validation_errors'}:result[key]=self.error_view(item,scope)
            elif key in {'evidence_ref_ids','shared_evidence_refs'}:
                # Edges and stories cite findings, with program-derived evidence.
                if 'claim_ids' in value or ('phase' in value and 'supporting_claim_ids' in value): continue
                values=item if is_claim else [raw for raw in item if raw.startswith(('event:','block:'))]
                result['support_ids' if key=='evidence_ref_ids' else key] = self._ids(values,'E',scope)
            elif key in {'supporting_claim_ids','claim_ids','contradicting_claim_ids'}:
                result['counter_ids' if key=='contradicting_claim_ids' else 'support_ids'] = self._ids(item,'C',scope)
            elif key in {'supporting_fact_ids','checked_fact_ids','source_fact_ids'}:
                result['support_ids'] = self._ids(item,'Q',scope)
            elif key=='fact_id': result['query_id'] = self.alias('Q',item,scope)
            elif key=='claim_id':
                result[key] = self.catalog.claim(value,scope) if is_claim else self.alias('C',item,scope)
            elif key=='lead_id': result[key] = self.alias('lead',item,scope)
            elif key in {'visible_fact_ids','investigation_fact_ids'}:
                result[key.replace('fact','query')] = self._ids(item,'Q',scope)
            elif key=='fact_ids': result['query_ids'] = self._ids(item,'Q',scope)
            elif key=='claim_groups_by_role':
                result[key] = {role:self._ids(ids,'C',scope) for role,ids in item.items()}
            elif key=='evidence_refs_by_claim': continue
            elif key=='cited_event_order_bounds':
                result[key] = {self.alias('C',cid,scope):bounds for cid,bounds in item.items()}
            elif key=='block_ids': continue
            elif key=='block_id' and isinstance(item,str):
                # A locator found in a query is not itself newly returned evidence.
                result[key] = self.catalog.register('E','block:'+item)
                self.block_locators.add(result[key])
            elif key=='event_ref_id': result[key] = self.catalog.register('E',item)
            else: result[key] = self.project(item,scope)
        if 'offset' in value and 'operation' in value and type(value['offset']) is int:
            raw = 'event:'+str(value['offset'])
            alias = self.catalog.forward.get(('E',raw))
            if alias in self.allowed['E']: result['evidence_id'] = alias
        return result

    def schema(self):
        schema = deepcopy(self.original['output_schema'])
        def visit(node):
            if isinstance(node,list):
                for item in node:visit(item)
                return
            if not isinstance(node,dict):return
            if node.get('type')=='object':
                props = node['properties']
                if 'verdict' in props and 'risk_summary' in props:
                    props.pop('supporting_claim_ids',None)
                elif set(props)=={'explanation','supporting_claim_ids'}:
                    props['role'] = enum(['support','counterevidence','context'])
                if 'coverage_ids' in props and 'source_fact_ids' in props:
                    props.pop('coverage_ids');props.pop('source_fact_ids')
                    props['support_ids'] = ref_array('gap_query_id')
                if 'supporting_block_ids' in props:
                    props.pop('supporting_block_ids');props.pop('evidence_ref_ids')
                    props['support_ids'] = ref_array('evidence_id',1)
                if 'claim_ids' in props or ('phase' in props and 'supporting_claim_ids' in props):
                    props.pop('evidence_ref_ids',None)
                for old,new,kind in [('claim_ids','support_ids','claim_id'),
                                     ('supporting_claim_ids','support_ids','claim_id'),
                                     ('contradicting_claim_ids','counter_ids','claim_id'),
                                     ('checked_fact_ids','support_ids','visible_query_id'),
                                     ('supporting_fact_ids','support_ids','query_id')]:
                    if old in props:
                        minimum=props[old].get('minItems',0)
                        props.pop(old);props[new]=ref_array(kind,minimum)
                node['required']=list(props)
            for key,item in node.items():
                if key!='$defs':visit(item)
        visit(schema)
        if self.stage=='investigation':
            branches=schema['properties']['response']['anyOf']
            branches[:]=[branch for branch in branches
                         if not ('claim_output' in branch['properties'] and not self.allowed['E'])
                         and not ('no_evidence' in branch['properties'] and not self.visible_queries)]
            if not branches:raise ValueError('No supported response is available in the current reference domain')
            self.effective_actions=list(dict.fromkeys(key for branch in branches for key in branch['properties']
                                                     if key!='investigation_closure'))
        elif not self.allowed['C']:
            for field in ['reasoning','attack_story','claim_connections']:
                if field in schema['properties']:schema['properties'][field]['maxItems']=0
        defs = {}
        for name,values in [('claim_id',self.allowed['C']),('query_id',self.allowed['Q']),
                            ('visible_query_id',self.visible_queries),('gap_query_id',self.gap_queries),
                            ('lead_id',self.allowed['lead'])]:
            bounded_ids(schema,defs,name,sorted(values))
        evidence = sorted(self.allowed['E'])
        # Avoid the provider's global enum-size limit on large investigations.
        # Exact per-call membership is checked locally before resolving aliases.
        if len(evidence)<=512:
            bounded_ids(schema,defs,'evidence_id',evidence)
        else:
            defs['evidence_id']={'type':'string','pattern':r'^E[0-9]{3,}$'}
        used=set()
        def references(node):
            if isinstance(node,dict):
                if '$ref' in node:used.add(node['$ref'].rsplit('/',1)[1])
                for key,item in node.items():
                    if key!='$defs':references(item)
            elif isinstance(node,list):
                for item in node:references(item)
        references(schema)
        defs={key:value for key,value in defs.items() if key in used}
        # Keep schemas within the service's global enum budget. Exact call-local
        # membership remains mandatory even when a large domain uses a pattern.
        total=sum(len(value.get('enum',[])) for value in defs.values())
        for key in sorted(defs,key=lambda key:len(defs[key].get('enum',[])),reverse=True):
            if total<=800:break
            values=defs[key].get('enum',[])
            prefix='E' if key=='evidence_id' else 'C' if key=='claim_id' else 'lead_' if key=='lead_id' else 'Q'
            defs[key]={'type':'string','pattern':'^'+prefix+r'[0-9]{3,}$'}
            total-=len(values)
        schema['$defs']=defs
        return schema

    def payload(self):
        p = self.project(self.original)
        p['structured_output'] = {**self.original['structured_output'],'reference_protocol':VERSION}
        p['output_schema'] = self.schema()
        if self.stage=='investigation':p['structured_output']['allowed_actions']=self.effective_actions
        p['reference_catalog'] = {
            'evidence':[{'id':alias,'kind':('event' if self.catalog.reverse[alias][1].startswith('event:') else
                                           'fragment' if self.catalog.reverse[alias][1].startswith('block:') else 'static')}
                        for alias in sorted(self.allowed['E'])],
            'claims':[{'id':alias,'support_ids':[self.catalog.forward[('E',raw)]
                         for raw in self.catalog.claims[self.catalog.reverse[alias][1]]]}
                      for alias in sorted(self.allowed['C'])],
            'query_ids':sorted(self.allowed['Q']),
        }
        # Behavioral standards remain those supplied by the original stages.
        instruction = self.original['instruction']
        instruction = instruction.replace(
            'Every top-level supporting_claim_id must also occur in reasoning[].supporting_claim_ids with an explanation.',
            'The program derives conclusion support only from reasoning entries whose role is support.')
        instruction = instruction.replace(
            'reasoning may discuss other known claims as context or counterevidence without adding them to top-level support.',
            'Mark each reasoning entry as support, counterevidence or context relative to the selected verdict.')
        instruction = instruction.replace(
            'All *_claim_ids accept claim IDs only; put coverage_ids and source_fact_ids in analysis_gaps instead.',
            'Use C references for behavioral reasoning and Q references for analysis gaps.')
        instruction = re.sub(r'[^.]*supporting_block_ids[^.]*\.', '', instruction)
        for old,new in [('event:* or block:*','E identifiers'),('event:* and block:*','E identifiers'),
                        ('fact_*','Q identifiers'),('investigation_fact_ids','investigation_query_ids'),
                        ('visible_fact_ids','visible_query_ids'),('supporting_fact_ids','support_ids'),
                        ('checked_fact_ids','support_ids'),('evidence_ref_ids','support_ids'),
                        ('supporting_claim_ids','support_ids'),('source_fact_ids','support_ids'),
                        ('coverage_ids','query IDs'),('reference_contract','reference_catalog')]:
            instruction = instruction.replace(old,new)
        p['instruction'] = instruction + (
            ' Unified references: E identifies returned event/fragment evidence; C identifies a validated finding; '
            'Q identifies a query result and its examined scope. support_ids accepts E for investigation claims, '
            'Q for no_evidence, closure and analysis_gaps, and C for decision reasoning, stories, relationships, '
            'review issues and review resolutions. counter_ids accepts C only. Choose only supplied identifiers. '
            'Do not repeat raw evidence references or a top-level support list in decision output. The program '
            'expands findings to their existing evidence; this is provenance bookkeeping, not proof of causality. '
            'Explain every asserted relation from the actual observations; preserve missing transitions and reject '
            'unsupported relations during independent review. A query with no matches is a scoped negative result; '
            'a failed or unperformed query is not a negative result. lead_id is a task bookkeeping handle, never evidence. '
            'Offsets and process keys are query locators. A block_id tool argument may use the returned E fragment handle.'
        )
        # Remove stale raw-ID policy text rather than presenting two vocabularies.
        if 'evidence_policy' in p:
            p['evidence_policy']=[item for item in p['evidence_policy'] if not any(word in item for word in ['event:*','block:*','fact_*'])]
        return p

    def resolve(self, response):
        result = deepcopy(response)
        def refs(values,kind):
            return [self.catalog.resolve(value,kind,self.allowed[kind]) for value in values]
        def evidence(claim_ids):
            return list(dict.fromkeys(raw for cid in claim_ids for raw in self.catalog.claims[cid]))
        if self.stage=='investigation':
            if 'claim_output' in result:
                for claim in result['claim_output']['claims']:
                    raw=refs(claim.pop('support_ids'),'E')
                    claim.update(evidence_ref_ids=raw,supporting_block_ids=[r[6:] for r in raw if r.startswith('block:')])
            if 'no_evidence' in result:
                body=result['no_evidence'];body['checked_fact_ids']=[self.catalog.resolve(alias,'Q',self.visible_queries).split(':',1)[1]
                    for alias in body.pop('support_ids')]
            for item in result.get('investigation_closure',{}).get('leads',[]):
                full=self.catalog.resolve(item['lead_id'],'lead',self.allowed['lead'])
                item['lead_id']=full.split(':',1)[1]
                item['supporting_fact_ids']=[r.split(':',1)[1] for r in refs(item.pop('support_ids'),'Q')]
            if 'tool_request' in result:
                args=result['tool_request']['arguments'];bid=args.get('block_id')
                if isinstance(bid,str) and re.fullmatch(r'E\d{3,}',bid):
                    raw=self.catalog.resolve(bid,'E',self.allowed['E']|self.block_locators)
                    if not raw.startswith('block:'):raise ValueError('block_id requires fragment evidence')
                    args['block_id']=raw[6:]
            return result
        support=[]
        for item in result.get('reasoning',[]):
            item['supporting_claim_ids']=refs(item.pop('support_ids'),'C')
            if item.pop('role')=='support':support.extend(item['supporting_claim_ids'])
        if self.stage!='review':result['supporting_claim_ids']=list(dict.fromkeys(support))
        for field in ['attack_story','claim_connections','issues','review_resolution']:
            for item in result.get(field,[]):
                ids=refs(item.pop('support_ids'),'C')
                item['claim_ids' if field=='claim_connections' else 'supporting_claim_ids']=ids
                if field in {'attack_story','claim_connections'}:
                    item['evidence_ref_ids']=evidence(ids)
                    if field=='claim_connections':
                        item['limitations'].append('Evidence was expanded from the cited claims; citation provenance does not establish causality.')
        for item in result.get('hypothesis_assessment',{}).values():
            item['supporting_claim_ids']=refs(item.pop('support_ids'),'C')
            item['contradicting_claim_ids']=refs(item.pop('counter_ids'),'C')
        for item in result.get('analysis_gaps',[]):
            queries=[self.catalog.resolve(alias,'Q',self.gap_queries) for alias in item.pop('support_ids')]
            item['source_fact_ids']=queries
            item['coverage_ids']=list(dict.fromkeys(q.split(':',1)[0]+':coverage' for q in queries
                if q.split(':',1)[0]+':coverage' in self.coverage_ids))
        return result

    def validate(self,response,projected):
        plain={key:value for key,value in response.items() if key!='_usage'}
        if self.stage=='investigation' and 'tool_request' in plain:
            plain=deepcopy(plain)
            body=plain['tool_request']
            for branch in projected['output_schema']['properties']['response']['anyOf']:
                tool=branch['properties'].get('tool_request',{}).get('properties',{})
                if body.get('tool_name') in tool.get('tool_name',{}).get('enum',[]):
                    # The SDK's canonical action has already omitted optional
                    # nulls. Restore those keys only in this validation copy.
                    for name in tool['arguments']['properties']:
                        body['arguments'].setdefault(name,None)
                    break
        validate_output({'response':plain} if self.stage=='investigation' else plain,projected['output_schema'])


class UnifiedReferenceClient:
    """One wrapper per pipeline/session; no shared cross-sample identifier state."""
    def __init__(self, client, audit_dir):
        self.client=client
        self.catalog=ReferenceCatalog()
        self.audit_dir=Path(audit_dir)/'reference_protocol'
        self.audit_dir.mkdir(parents=True,exist_ok=True)
        self.sequence=0
        saved=self.audit_dir/'registry.json'
        if saved.exists():
            data=json.loads(saved.read_text())
            if data.get('version')!=VERSION:raise ValueError('Incompatible reference catalog')
            for entry in data['references']:
                key=(entry['kind'],entry['canonical']);alias=entry['id']
                if key in self.catalog.forward or alias in self.catalog.reverse:
                    raise ValueError('Non-bijective saved reference catalog')
                self.catalog.forward[key]=alias;self.catalog.reverse[alias]=key
            self.catalog.claims={key:tuple(value) for key,value in data['claim_evidence'].items()}
            self.catalog.role_evidence={key:set(value) for key,value in data.get('role_evidence',{}).items()}
            self.sequence=max([int(path.name.split('-')[0]) for path in self.audit_dir.glob('*-model-input.json')],default=0)

    def _save(self,path,value):
        target=self.audit_dir/path
        tmp=target.with_suffix('.tmp')
        tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
        tmp.replace(target)

    def complete_json(self,messages):return self._call(messages,False)
    def complete_json_once(self,messages):return self._call(messages,True)

    def _call(self,messages,once):
        payload=json.loads(messages[-1]['content'])
        if 'structured_output' not in payload:
            return (getattr(self.client,'complete_json_once',self.client.complete_json) if once else self.client.complete_json)(messages)
        with self.catalog.lock:
            view=ReferenceView(self.catalog,payload)
            projected=view.payload()
            self.sequence+=1;seq=self.sequence
            self._save(Path('registry.json'),self.catalog.snapshot())
            self._save(Path(f'{seq:04d}-model-input.json'),projected)
        forwarded=tuple(messages[:-1])+({'role':messages[-1]['role'],'content':json.dumps(projected,sort_keys=True)},)
        start=time.monotonic()
        try:
            complete=getattr(self.client,'complete_json_once',self.client.complete_json) if once else self.client.complete_json
            response=complete(forwarded)
            self._save(Path(f'{seq:04d}-model-output.json'),response)
            # The SDK already validated and removed only the transport wrapper.
            # Resolve exclusively against the current call's allowed domains.
            view.validate(response,projected)
            result=view.resolve(response)
            self._save(Path(f'{seq:04d}-resolved-output.json'),result)
            self._save(Path(f'{seq:04d}-status.json'),{'status':'resolved','elapsed_seconds':time.monotonic()-start})
            return result
        except Exception as exc:
            self._save(Path(f'{seq:04d}-status.json'),{'status':'failed','error_type':type(exc).__name__,
                'elapsed_seconds':time.monotonic()-start,'raw_response_content':getattr(exc,'raw_response_content',None)})
            raise
