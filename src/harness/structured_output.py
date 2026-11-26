"""Versioned, closed JSON schemas shared by model prompts and API requests.

Strict investigator responses use {"response": <one canonical action>} because
OpenAI requires an object root rather than a root anyOf. Only that transport
wrapper is removed; evidence, claims and decision semantics are not rewritten.
"""
from __future__ import annotations

from copy import deepcopy
import inspect
import re

VERSION = 'ransift-strict-json-v032'


def obj(properties):
    return {'type':'object', 'properties':properties, 'required':list(properties), 'additionalProperties':False}


def string(description=''):
    value = {'type':'string', 'pattern':r'\S'}
    if description:
        value['description'] = description
    return value


def enum(values):
    return {'type':'string', 'enum':list(dict.fromkeys(values))}


def array(items=None, minimum=0):
    return {'type':'array', 'items':items or string(), 'minItems':minimum}


def ref_array(name, minimum=0):
    return array({'$ref':'#/$defs/'+name}, minimum)


def id_definition(values, description):
    # An empty enum is invalid JSON Schema. The empty-domain array itself is
    # bounded to zero when no valid identifier exists.
    return {**(enum(values) if values else string()), 'description':description}


def bounded_ids(schema, definitions, name, values):
    definitions[name] = id_definition(values, name)
    if not values:
        def visit(node):
            if isinstance(node,dict):
                if node.get('items') == {'$ref':'#/$defs/'+name}:
                    node.update(maxItems=0, minItems=0)
                for child in node.values(): visit(child)
            elif isinstance(node,list):
                for child in node: visit(child)
        visit(schema)


def argument_type(declaration):
    parts = declaration.split('|')
    atoms = {'str':{'type':'string'}, 'int':{'type':'integer'}, 'bool':{'type':'boolean'},
             'null':{'type':'null'}, 'list[str]':array({'type':'string'})}
    if all(part in atoms for part in parts):
        return atoms[parts[0]] if len(parts)==1 else {'anyOf':[deepcopy(atoms[p]) for p in parts]}
    if any(part in atoms for part in parts):
        raise ValueError('Unsupported tool argument declaration: '+declaration)
    return enum(parts)


def tool_schema(spec, registry):
    # Use the effective callable's signature, including defaults, rather than
    # guessing whether a described argument may be omitted.
    function = getattr(registry.tools, spec['name'])
    parameters = inspect.signature(function).parameters
    if set(parameters) != set(spec['parameters']):
        raise ValueError('Tool declaration/signature mismatch: '+spec['name'])
    properties = {}
    for name, declaration in spec['parameters'].items():
        value = argument_type(declaration)
        parameter = parameters[name]
        if parameter.default is not inspect.Parameter.empty:
            # All JSON keys are required. null means omit the argument and use
            # its existing Python default; explicit false/0/[] are preserved.
            value = {'anyOf':[value, {'type':'null'}],
                     'description':'null omits this argument and preserves the existing tool default.'}
        properties[name] = value
    return obj({'tool_request':obj({'tool_name':enum([spec['name']]),
                                   'arguments':obj(properties), 'purpose':string()})})


def agent_schema(payload, registry):
    prior = payload.get('structured_output', {})
    allowed = payload.get('output_schema',{}).get('one_of', prior.get('allowed_actions',[]))
    if not allowed:
        raise ValueError('Investigation schema requires explicit allowed actions')
    working = payload['working_context']
    require_closure = 'investigation_closure' in payload['output_schema'] or prior.get('require_closure',False)
    claim = obj({
        'claim_type':string(), 'statement':string(), 'observed_operations':array(string(),1),
        'behavior_interpretation':string(),
        'evidence_ref_ids':array({'type':'string','pattern':r'^(event:|block:).+'},1),
        'supporting_block_ids':array(string('Raw returned block identifier, without block: prefix.')),
        'alternative_explanations':array(), 'uncertainty':array(),
    })
    closure = obj({'leads':array(obj({
        'lead_id':{'$ref':'#/$defs/lead_id'},
        'status':enum(['investigated','not_relevant','unresolved']),
        'explanation':string(), 'supporting_fact_ids':ref_array('fact_id',1),
        'next_step':{'type':'string','description':'Concrete next step when unresolved; otherwise empty.'},
    })), 'limitations':array()})
    lead_count = len(working.get('followup_leads',[]))
    closure['properties']['leads'].update(minItems=lead_count,maxItems=lead_count)
    branches = []
    if 'tool_request' in allowed:
        branches.extend(tool_schema(spec,registry) for spec in payload['available_tools'])
    for kind, body in [
        ('claim_output',obj({'claims':array(claim,1)})),
        ('no_evidence',obj({'checked_fact_ids':ref_array('fact_id',1), 'scope':string(), 'uncertainty':array()})),
    ]:
        if kind not in allowed:
            continue
        properties = {kind:body}
        if require_closure:
            properties['investigation_closure'] = closure
        branches.append(obj(properties))
    if not branches:
        raise ValueError('No permitted investigation response branch')
    schema = obj({'response':{'anyOf':branches}})
    definitions = {}
    bounded_ids(schema,definitions,'fact_id',working.get('investigation_fact_ids',working.get('visible_fact_ids',[])))
    bounded_ids(schema,definitions,'lead_id',[lead['lead_id'] for lead in working.get('followup_leads',[])])
    schema['$defs'] = definitions
    payload['output_schema'] = schema
    payload['structured_output'] = {'version':VERSION, 'stage':'investigation', 'unwrap_response':True,
                                    'allowed_actions':allowed, 'require_closure':require_closure}
    payload['instruction'] += (
        ' The formal output_schema is authoritative for JSON structure. Return exactly '
        '{"response": <one permitted action object>}. Put investigation_closure beside the '
        'terminal action INSIDE response. Tool-request arguments must use the per-tool schema; '
        'null means omit an optional argument and retain its existing default. '
        'Use only the permitted response branches; never combine actions.'
    )
    return payload


def decision_schema(payload, stage):
    prior = payload['output_schema']
    ids = ref_array('claim_id')
    issue = obj({'description':string(), 'impact':enum(['changes_verdict','report_only']),
                 'supporting_claim_ids':deepcopy(ids)})
    if stage == 'review':
        schema = obj({'verdict_assessment':enum(['supported','unsupported','undetermined']),
                      'summary':string(), 'issues':array(issue)})
    else:
        schema = obj({
            'verdict':enum(['malicious','benign']), 'risk_summary':string(),
            'supporting_claim_ids':deepcopy(ids),
            'reasoning':array(obj({'explanation':string(),'supporting_claim_ids':ref_array('claim_id',1)})),
            'attack_story':array(obj({'phase':string(),'action':string(),
                'supporting_claim_ids':ref_array('claim_id',1),
                'evidence_ref_ids':array({'type':'string','pattern':r'^(event:|block:).+'},1)})),
            'benign_alternatives':array(), 'uncertainties':array(),
            'analysis_status':enum(['complete','incomplete']),
            'analysis_gaps':array(obj({'description':string(), 'impact':enum(['material','limitation']),
                'coverage_ids':ref_array('coverage_id'), 'source_fact_ids':ref_array('source_fact_id')})),
        })
    properties = schema['properties']
    if 'claim_connections' in prior:
        properties['claim_connections'] = array(obj({
            'claim_ids':ref_array('claim_id',2),
            'relation':enum(['process_delegation','shared_object','temporal_sequence','overlapping_observation','same_process']),
            'evidence_ref_ids':array({'type':'string','pattern':r'^(event:|block:).+'},1),
            'explanation':string(), 'limitations':array(),
        }))
    if 'hypothesis_assessment' in prior:
        hypothesis = obj({'supporting_claim_ids':deepcopy(ids), 'contradicting_claim_ids':deepcopy(ids),
                          'explanation':string(), 'unconfirmed_assumptions':array()})
        properties['hypothesis_assessment'] = obj({label:deepcopy(hypothesis) for label in ['malicious','benign']})
    if stage == 'final':
        count = len(payload['evidence_review']['issues'])
        properties['review_resolution'] = array(obj({'issue_index':{'type':'integer','minimum':0, 'maximum':max(0,count-1)},
            'resolution':string(), 'supporting_claim_ids':deepcopy(ids)}))
        properties['review_resolution'].update(minItems=count,maxItems=count)
    schema['required'] = list(properties)
    definitions = {}
    contract = payload.get('reference_contract',{})
    for name, values in [('claim_id',[c['claim_id'] for c in payload['claims']]),
                         ('coverage_id',contract.get('coverage_ids',[])),
                         ('source_fact_id',contract.get('source_fact_ids',[]))]:
        bounded_ids(schema,definitions,name,values)
    schema['$defs'] = definitions
    payload['output_schema'] = schema
    payload['structured_output'] = {'version':VERSION,'stage':stage,'unwrap_response':False}
    payload['instruction'] += ' Return exactly the formal output_schema; all declared fields are required and additional fields are prohibited.'
    return payload


def response_format(payload):
    meta = payload.get('structured_output')
    if meta is None:
        return {'type':'json_object'}
    if meta.get('version') != VERSION:
        raise ValueError('Unknown structured-output contract')
    suffix = 'v033' if meta.get('reference_protocol')=='ransift-unified-references-v033' else 'v032'
    return {'type':'json_schema','json_schema':{
        'name':'ransift_'+meta['stage']+'_'+suffix, 'strict':True, 'schema':payload['output_schema']}}


def validate_output(value, schema, root=None, path='$'):
    """Validate only the JSON Schema subset emitted by this module.

    This independent local boundary catches ignored API constraints; semantic
    reference ownership and evidence interpretation remain in existing code.
    """
    root = schema if root is None else root
    if '$ref' in schema:
        return validate_output(value,root['$defs'][schema['$ref'].rsplit('/',1)[1]],root,path)
    if 'anyOf' in schema:
        for branch in schema['anyOf']:
            try:
                validate_output(value,branch,root,path)
                return
            except ValueError:
                pass
        raise ValueError(path+': no permitted schema branch matches')
    kind = schema['type']
    types = {'object':dict,'array':list,'string':str,'integer':int,'boolean':bool,'null':type(None)}
    if not isinstance(value,types[kind]) or (kind=='integer' and isinstance(value,bool)):
        raise ValueError(path+': invalid '+kind+' type')
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError(path+': value outside enum')
    if kind == 'object':
        if set(value) != set(schema['properties']):
            raise ValueError(path+': missing or additional fields')
        for name,item in value.items():
            validate_output(item,schema['properties'][name],root,path+'.'+name)
    elif kind == 'array':
        if len(value)<schema.get('minItems',0) or len(value)>schema.get('maxItems',float('inf')):
            raise ValueError(path+': invalid array length')
        for index,item in enumerate(value):
            validate_output(item,schema['items'],root,f'{path}[{index}]')
    elif kind == 'string' and 'pattern' in schema and not re.search(schema['pattern'],value):
        raise ValueError(path+': invalid string pattern')
    elif kind == 'integer' and not schema.get('minimum',-float('inf')) <= value <= schema.get('maximum',float('inf')):
        raise ValueError(path+': integer out of range')


def decode_output(data, payload):
    meta = payload.get('structured_output')
    if meta is None:
        return data
    validate_output(data,payload['output_schema'])
    if not meta['unwrap_response']:
        return data
    result = deepcopy(data['response'])
    if 'tool_request' in result:
        result['tool_request']['arguments'] = {key:value for key,value in result['tool_request']['arguments'].items() if value is not None}
    return result
