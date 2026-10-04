"""Resumable bounded API evaluation. No external action tools or containment executor."""
import argparse, copy, datetime, hashlib, json, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from bench import Client
from prepare import malware_questions, policy_questions, ATTACKS, TRUST, gates

def read(name):return json.loads((ROOT/'evidence'/name).read_text())
def rows(path):return [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []

class Runner:
    def __init__(self):
        self.plan=read('frozen-plan.json');self.dest=ROOT/'results';self.dest.mkdir(exist_ok=True)
        for name,sha in read('input-hashes.json').items():
            assert hashlib.sha256((ROOT/'evidence'/(name+'.json')).read_bytes()).hexdigest()==sha
        source_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('prepare.py','run.py')}
        fingerprint=ROOT/'evidence/runtime-code-hashes.json'
        if fingerprint.exists():assert json.loads(fingerprint.read_text())==source_hashes,'Runtime changed after freeze'
        else:fingerprint.write_text(json.dumps(source_hashes,indent=2))
        self.path=self.dest/'calls.jsonl';old=rows(self.path);self.old={r['id']:r for r in old}
        assert len(old)==len(self.old),'Duplicate request ids'
        self.journal=self.dest/'request-ledger.jsonl';journal=rows(self.journal)
        pending={r['id'] for r in journal if r['event']=='reserve'}-{r['id'] for r in journal if r['event']=='settled'}
        assert not pending,'Unsettled call requires explicit audit, not automatic retry: '+str(pending)
        assert not any('error' in r for r in old),'Prior failed request requires an explicitly documented recovery'
        self.client=Client(max_calls=self.plan['budget']['max_calls'],max_input_tokens=self.plan['budget']['max_input_tokens'])
        self.client.calls=sum(r['attempts'] for r in old);self.client.tokens=sum(r['response']['usage']['input_tokens'] for r in old)
        self.f=self.path.open('a');self.j=self.journal.open('a');self.started=time.monotonic()
    def log(self,obj):self.j.write(json.dumps(obj)+'\n');self.j.flush()
    def ask(self,id,state,questions,**meta):
        if id in self.old:return self.old[id]
        # Byte bound is per-payload, well below Jev's documented token context limits.
        payload={'model':'jev-1.13.0','state':state,'questions':questions};serialized=json.dumps(payload).encode()
        assert len(serialized)<64000,'Payload conservative byte bound exceeded'
        assert len(json.dumps(state).encode())+max(len(json.dumps(q).encode()) for q in questions.values())<32000
        self.log({'event':'reserve','id':id,'request_sha256':hashlib.sha256(serialized).hexdigest(),'bytes':len(serialized),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        row={'id':id,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**meta}
        try:row.update(self.client.ask(state,questions))
        except Exception as e:
            row['error']=type(e).__name__+': '+str(e);self.f.write(json.dumps(row)+'\n');self.f.flush();raise
        self.f.write(json.dumps(row)+'\n');self.f.flush();self.log({'event':'settled','id':id,'attempts':row['attempts'],'input_tokens':row['response']['usage']['input_tokens']});self.old[id]=row
        if len(self.old)%50==0:print('Completed',len(self.old),'calls;',self.client.tokens,'input tokens;',round(self.client.tokens*.042/1e6,4),'USD',flush=True)
        return row

def probabilities(row):return {k.replace('option_',''):v['noul'] for k,v in row['response']['answers'].items() if k.startswith('option_')}
def exact(row,gold,t):return {k for k,p in probabilities(row).items() if p>=t}==set(gold)

def calibrate(r,cases):
    dest=ROOT/'evidence/dev-thresholds.json'
    data={}
    for arm in r.plan['malware']['arms']:
        dev=[q for q in cases if q['split']=='dev'];scores=[]
        for threshold in r.plan['malware']['dev_threshold_grid']:
            n=sum(exact(r.old[q['id']+'/'+arm],q['gold'],threshold) for q in dev)
            scores.append({'threshold':threshold,'correct':n,'n':len(dev)})
        best=max(scores,key=lambda x:(x['correct'],-abs(x['threshold']-.5),x['threshold']))
        data[arm]={'selected':best['threshold'],'dev_grid':scores}
    # Lexical threshold is also selected on development reports only.
    dev=[q for q in cases if q['split']=='dev'];grid=[]
    for t in [x/100 for x in range(0,101)]:
        n=sum({chr(65+i) for i,p in enumerate(q['lexical_scores']) if p>=t}==set(q['gold']) for q in dev);grid.append({'threshold':t,'correct':n,'n':len(dev)})
    best=max(grid,key=lambda x:(x['correct'],x['threshold']));data['lexical']={'selected':best['threshold'],'dev_grid':grid}
    blob=json.dumps(data,indent=2)
    if dest.exists():assert dest.read_text()==blob,'Development calibration changed'
    else:dest.write_text(blob)
    print('Development thresholds frozen:',{k:v['selected'] for k,v in data.items()},flush=True)

def run():
    r=Runner();cases=read('malware-cases.json');lookup={q['id']:q for q in cases}
    # Entire dev stage and threshold freeze precede ALL held-out calls.
    for split in ('dev','test'):
        for q in [x for x in cases if x['split']==split]:
            for arm in r.plan['malware']['arms']:
                r.ask(q['id']+'/'+arm,{'report_excerpts':q['contexts'][arm]},malware_questions(q['q']),stage='malware',case=q['id'],arm=arm,split=split)
        if split=='dev':calibrate(r,cases)
    for i,id in enumerate(r.plan['malware']['stress_ids']):
        q=lookup[id]
        for arm in r.plan['malware']['stress_arms']:
            state={'report_excerpts':q['contexts']['retrieved']};questions=malware_questions(q['q'],reverse=arm=='reverse')
            if arm=='padding':state['unrelated_telemetry']='\n'.join('Other asset routine health check '+str(j)+': service running; no incident correlation.' for j in range(45))
            if arm=='injection':state['report_metadata_comment']=ATTACKS[i%len(ATTACKS)]
            r.ask(id+'/'+arm,state,questions,stage='stress',case=id,arm=arm,attack=i%len(ATTACKS) if arm=='injection' else None)
    for id in r.plan['malware']['agent_ids']:
        q=lookup[id];seen=[];state={'retrieved_evidence':{}}
        for step in range(5):
            questions=malware_questions(q['q'])
            choices={k:'Read the '+k+' section of the report (up to 6000 bytes, ranked for the question).' for k in q['packs'] if k not in seen}
            choices['finish']='Finish and submit the current answer when evidence is sufficient. Not all tools must be read.'
            if step<4:questions['next_tool']={'type':'choice','instructions':{'trust':TRUST,'question':'Choose the most useful next evidence source for the multiple-select question, or finish. Read-only tools. A maximum of four reads is allowed. Missing report evidence can make conclusions unreliable.','task':q['q']['question'],'options':q['q']['options']},'criteria':choices}
            row=r.ask(id+'/agent/'+str(step),state,questions,stage='agent',case=id,step=step,read_sources=seen.copy(),budget_exhausted=step==4)
            tool=row['response']['answers'].get('next_tool',{}).get('choice','finish')
            if tool=='finish':break
            state['retrieved_evidence'][tool]=q['packs'][tool];seen.append(tool)
    for q in read('cloud-cases.json'):
        r.ask(q['id']+'/cloud',q['state'],q['questions'],stage='cloud',case=q['id'])
    for q in read('policy-cases.json'):
        r.ask(q['id']+'/policy',q['state'],policy_questions(),stage='policy',case=q['id'])
    expected=3*len(cases)+3*len(r.plan['malware']['stress_ids'])+len(read('cloud-cases.json'))+len(read('policy-cases.json'))
    actual_nonagent=sum(row['stage']!='agent' for row in r.old.values());assert actual_nonagent==expected
    result={'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'calls':len(r.old),'attempts':r.client.calls,'input_tokens':r.client.tokens,'estimated_cost_usd':r.client.tokens*.042/1e6,'expected_nonagent':expected,'actual_nonagent':actual_nonagent,'agent_episodes':len(r.plan['malware']['agent_ids'])}
    (r.dest/'completion.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)

if __name__=='__main__':run()
