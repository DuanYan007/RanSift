"""Read-only ransom-content extraction. No labels, execution, rendering or HTTP.

CFGS is a supported encrypted resource format, not a family verdict. Decode is
accepted only with its embedded checksum and all three section boundaries valid.
"""
from __future__ import annotations
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess

SCHEMA='harness-static-ransom-information-v035'
MAX_FILE=256*1024*1024
MAX_RESOURCE=4*1024*1024
MAX_CONTENT=16384
MAX_TOTAL_TEXT=65536
PATTERNS={
 'encrypted_files':r'(?:your|all|these)\s+(?:important\s+)?files\s+(?:(?:have|has)\s+been\s+|are\s+|were\s+)?encrypted',
 'paid_decryption':r'(?:pay(?:ment)?|price|purchase|bitcoin|monero|ransom).{0,180}(?:decrypt|recover|restore)|(?:decrypt|recover|restore).{0,180}(?:pay(?:ment)?|price|purchase|bitcoin|monero|ransom)',
 'time_pressure':r'price.{0,100}(?:increas|hour|soon)|(?:deadline|within\s+\d+\s+hours)',
 'data_disclosure':r'(?:data|files).{0,100}(?:auction|publish|leak)|(?:auction|publish|leak).{0,100}(?:data|files)',
}

def digest(b):return hashlib.sha256(b).hexdigest()

class VisibleText(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.hidden=0;self.parts=[]
 def handle_starttag(self,tag,attrs):
  if tag.lower() in {'script','style'}:self.hidden+=1
 def handle_endtag(self,tag):
  if tag.lower() in {'script','style'}:self.hidden=max(0,self.hidden-1)
 def handle_data(self,data):
  if not self.hidden and data.strip():self.parts.append(' '.join(data.split()))

def visible(text):
 if not re.search(r'<(?:html|body|hta|script|div|p|style)\b',text,re.I):return text
 p=VisibleText();p.feed(text);p.close();return '\n'.join(p.parts)

def indicators(text):
 return [{'category':name,'excerpt':text[max(0,m.start()-80):min(len(text),m.end()+80)],'character_offset':m.start()}
         for name,pattern in PATTERNS.items() for m in list(re.finditer(pattern,text,re.I|re.S))[:8]]

def aes_tail(data,key,iv):
 if len(key)!=32 or len(iv)!=16 or not data:raise ValueError('Invalid encrypted resource header')
 n=len(data)//16*16
 run=lambda args,b:subprocess.run(['openssl','enc',*args],input=b,capture_output=True,check=True,timeout=10).stdout
 out=run(['-d','-aes-256-cbc','-nopad','-K',key.hex(),'-iv',iv.hex()],data[:n]) if n else b''
 if n<len(data):
  block=data[n-16:n] if n else iv
  stream=run(['-aes-256-ecb','-nopad','-K',key.hex()],block)
  out+=bytes(a^b for a,b in zip(data[n:],stream))
 if len(out)!=len(data):raise ValueError('Decrypted resource length differs')
 return out

def decode_cfgs(resource):
 if len(resource)<100 or len(resource)>MAX_RESOURCE:raise ValueError('CFGS resource outside bounded format')
 first=aes_tail(resource[48:],resource[:32],resource[32:48])
 if len(first)<49:raise ValueError('Missing second encrypted header')
 second=aes_tail(first[48:],first[16:48],first[:16])
 at=1+second[0]
 if at+16>len(second):raise ValueError('Checksum header exceeds data')
 payload=second[at+16:]
 if hashlib.md5(payload).digest()!=second[at:at+16]:raise ValueError('CFGS embedded checksum mismatch')
 sections=[];offset=0
 for _ in range(3):
  if offset+4>len(payload):raise ValueError('Missing section length')
  n=int.from_bytes(payload[offset:offset+4],'big');offset+=4
  if n<=0 or offset+n>len(payload):raise ValueError('Section bounds invalid')
  sections.append(payload[offset:offset+n]);offset+=n
 if offset!=len(payload):raise ValueError('Trailing unparsed configuration bytes')
 return sections

def scan_ransom_information(path):
 path=Path(path)
 if path.stat().st_size>MAX_FILE:raise ValueError('Static input exceeds 256MiB bound')
 data=path.read_bytes();file_sha=digest(data);contents=[];diagnostics=[];seen=set()
 # Identity strings and filenames are only context, not evidence of extortion.
 target_names=sorted(set(m.group().decode('ascii','ignore').lower() for m in re.finditer(rb'[A-Za-z0-9_!#@. -]{1,100}\.(?:hta|html|txt)',data,re.I)))
 wide=data.decode('utf-16le','ignore')
 target_names+=re.findall(r'[A-Za-z0-9_!#@. -]{1,100}\.(?:hta|html|txt)',wide,re.I)
 target_names=sorted(set(n.strip().casefold() for n in target_names))[:64]
 def add(raw,source,encoding,text=None,validation=None):
  if digest(raw) in seen:return
  decoded=text if text is not None else raw.decode(encoding,errors='replace')
  readable=visible(decoded);hits=indicators(readable)
  if not hits:return
  remaining=MAX_TOTAL_TEXT-sum(len(x['readable_text']) for x in contents)
  if remaining<=0:return
  text_limit=min(MAX_CONTENT,remaining)
  seen.add(digest(raw));ref='static:ransom:'+str(len(contents)+1).zfill(4)
  # Full bounded text, not only a rule name, reaches all decision stages.
  contents.append(dict(ref_id=ref,binary_sha256=file_sha,source=source,encoding=encoding,content_sha256=digest(raw),
    original_bytes=len(raw),readable_text=readable[:text_limit],text_characters=len(readable),
    text_truncated=len(readable)>text_limit,indicators=hits,validation=validation or {'decoded':False},
    candidate_artifact_names=target_names,
    content_scope='content in supplied executable; not captured runtime output',
    runtime_execution_proven=False,code_to_write_path_verified=False,
    limitations=['Static content alone does not prove deployment, encryption or data exfiltration.']))
 for encoding,regex in [('ascii',rb'[\x09\x0a\x0d\x20-\x7e]{8,}'),('utf-16le',rb'(?:[\x09\x0a\x0d\x20-\x7e]\x00){8,}')]:
  for m in re.finditer(regex,data):
   raw=m.group();step=MAX_CONTENT*(2 if encoding=='utf-16le' else 1)
   # Bounded overlapping windows retain source offsets for long sections.
   for start in range(0,len(raw),max(1,step-1024)):
    add(raw[start:start+step],{'kind':'binary_string','file_offset':m.start()+start},encoding)
    if len(contents)>=32:break
   if len(contents)>=32:break
 if data[:2]==b'MZ':
  try:
   import pefile
   pe=pefile.PE(data=data,fast_load=True)
   try:
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    count=0
    for typ in getattr(getattr(pe,'DIRECTORY_ENTRY_RESOURCE',None),'entries',[]):
     for name in getattr(getattr(typ,'directory',None),'entries',[]):
      if str(name.name)!='CFGS':continue
      for lang in getattr(getattr(name,'directory',None),'entries',[]):
       count+=1
       if count>16:raise ValueError('Too many CFGS resources')
       s=lang.data.struct
       if s.Size>MAX_RESOURCE:raise ValueError('CFGS resource exceeds bound')
       resource=pe.get_data(s.OffsetToData,s.Size)
       sections=decode_cfgs(resource)
       add(sections[2],{'kind':'decoded_pe_resource','resource_name':'CFGS','resource_type':str(typ.name or typ.id),
         'language':lang.id,'resource_rva':s.OffsetToData,'resource_file_offset':pe.get_offset_from_rva(s.OffsetToData),
         'resource_sha256':digest(resource),'decoded_section':3},'utf-8-sig',
         validation={'embedded_md5_verified':True,'all_section_boundaries_verified':True,'section_bytes':[len(x) for x in sections]})
    diagnostics.append({'decoder':'CFGS','resources_examined':count,'status':'completed'})
   finally:pe.close()
  except (ValueError,ImportError,subprocess.SubprocessError,OSError) as exc:
   diagnostics.append({'decoder':'CFGS','status':'unavailable_or_invalid','error_type':type(exc).__name__})
  except Exception as exc:
   diagnostics.append({'decoder':'PE_resources','status':'invalid_or_unsupported','error_type':type(exc).__name__})
 return {'schema_version':SCHEMA,'binary_sha256':file_sha,'binary_bytes':len(data),'contents':contents,
  'content_count':len(contents),'text_budget_characters':MAX_TOTAL_TEXT,'diagnostics':diagnostics,'input_identity':'supplied_static_binary; runtime byte identity is not established here',
  'coverage':'bounded ASCII/UTF16 strings and supported CFGS resources; no-match is not proof of absence',
  'sample_executed':False,'network_requests':0}


def static_claims(report):
 return [dict(claim_id='static_ransom_'+str(i).zfill(4),agent_id='ransom_note_static',claim_type='static_ransom_content',
   statement='The supplied executable contains the following ransom-related text: '+c['readable_text'][:2000],
   evidence_ref_ids=[c['ref_id']],supporting_block_ids=[],static_ransom_information=c,
   alternative_explanations=['A stored text template may be unused or copied; check dynamic deployment and input identity.'],
   uncertainty=c['limitations'],status='candidate',behavior_class='unclassified',risk_primitives=[],dual_use_primitives=[]) for i,c in enumerate(report['contents'],1)]
