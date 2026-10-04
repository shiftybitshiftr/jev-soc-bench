"""Post-primary exploratory preprocessing ablation. Never replaces preregistered results."""
import copy,datetime,hashlib,json,re,sys,time
from pathlib import Path
from prepare import ROOT,PUBLIC,select,chunks,malware_questions,save_frozen
sys.path.insert(0,str(ROOT.parent))
from bench import Client

def compact(q):
    report=json.loads((PUBLIC/q['family']/q['report_id']).read_text())
    def shrink(v):return re.sub(r'[a-fA-F0-9]{32,}','[HASH]',str(v))
    mappings=list(dict.fromkeys(' / '.join(str(x.get(k,'')) for k in ('tactic','technique','attck_id')) for x in report.get('mitre_attcks',[])))
    names=list(dict.fromkeys(shrink(x.get('name','')) for x in report.get('signatures',[])))
    processes=list(dict.fromkeys(shrink(' | '.join(str(x.get(k,'')) for k in ('name','normalized_path','command_line'))) for x in report.get('processes',[])))
    index={'sandbox_summary':{k:report[k] for k in ('type','av_detect','vx_family','verdict','total_processes','total_signatures') if k in report},'reported_mitre':mappings,'signature_names':names,'processes':processes}
    core=json.dumps(index,ensure_ascii=True);query=q['q']['question']+' '+' '.join(q['q']['options']);omitted=False
    if len(core.encode())>20000:
        core,ids=select(chunks(index),query,budget=20000);omitted=True
    details=[shrink(x.get('name',''))+': '+shrink(x.get('description',''))[:1000] for x in report.get('signatures',[])]
    detail,chosen=select(details,query,budget=max(0,24000-len(core.encode())-100))
    return {'compact_evidence_index':core,'selected_details':detail},{'all_index_retained':not omitted,'techniques':len(mappings),'signatures':len(names),'detail_count':len(chosen),'bytes':len(core.encode())+len(detail.encode())}

def main():
    completion=json.loads((ROOT/'results/completion.json').read_text());cases=json.loads((ROOT/'evidence/malware-cases.json').read_text())
    plan={'version':'exploratory-compact-v1','reason':'Primary error audit found gold-relevant evidence omitted by lexical chunks. This post-outcome adapter change is exploratory, not a fresh confirmatory holdout.',
          'primary_calls_before_followup':completion['calls'],'arms':['compact'],'questions':'Identical to frozen primary questions, no all-of-above prompt changes.','cases':609,'byte_budget':24000,
          'method':'Preserve all unique MITRE mappings and signature names plus process names and sandbox summary where index <=20000 bytes; otherwise query-rank index chunks. Fill remaining budget with query-ranked signature details. Redact long hash strings. No answer labels used.',
          'primary_threshold':.5,'dev_thresholds':[round(x/100,2) for x in range(10,96,5)],'test_use':'Same original report-disjoint split; test-informed adapter design is disclosed. All-of-above exclusions are post-hoc sensitivities.'}
    save_frozen(ROOT/'evidence/followup-plan.json',plan);contexts={q['id']:compact(q) for q in cases};save_frozen(ROOT/'evidence/compact-contexts.json',contexts)
    save_frozen(ROOT/'evidence/followup-code-hash.json',{'sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    path=ROOT/'results/followup-calls.jsonl';old=[json.loads(x) for x in path.read_text().splitlines()] if path.exists() else [];cache={r['id']:r for r in old};assert len(cache)==len(old)
    journal_path=ROOT/'results/followup-ledger.jsonl';journal=[json.loads(x) for x in journal_path.read_text().splitlines()] if journal_path.exists() else []
    assert {x['id'] for x in journal if x['event']=='reserve'}=={x['id'] for x in journal if x['event']=='settled'},'Unsettled call requires audit'
    client=Client(max_calls=3500,max_input_tokens=35000000);client.calls=completion['attempts']+sum(r['attempts'] for r in old);client.tokens=completion['input_tokens']+sum(r['response']['usage']['input_tokens'] for r in old)
    f=path.open('a');ledger=journal_path.open('a')
    for split in ('dev','test'):
        for q in [q for q in cases if q['split']==split]:
            id=q['id']+'/compact'
            if id in cache:continue
            state,meta=contexts[q['id']];questions=malware_questions(q['q']);payload={'model':'jev-1.13.0','state':state,'questions':questions}
            assert len(json.dumps(state).encode())+max(len(json.dumps(x).encode()) for x in questions.values())<32000
            ledger.write(json.dumps({'event':'reserve','id':id,'request_sha256':hashlib.sha256(json.dumps(payload).encode()).hexdigest()})+'\n');ledger.flush()
            row={'id':id,'case':q['id'],'arm':'compact','split':split,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'context_meta':meta};row.update(client.ask(state,questions))
            f.write(json.dumps(row)+'\n');f.flush();ledger.write(json.dumps({'event':'settled','id':id,'input_tokens':row['response']['usage']['input_tokens']})+'\n');ledger.flush();cache[id]=row
            if len(cache)%50==0:print('Compact follow-up',len(cache),'/ 609; cumulative cost',round(client.tokens*.042/1e6,3),flush=True)
        if split=='dev':
            values=[]
            for t in plan['dev_thresholds']:
                count=sum({k[7:] for k,v in cache[q['id']+'/compact']['response']['answers'].items() if v['noul']>=t}==set(q['gold']) for q in cases if q['split']=='dev');values.append({'threshold':t,'correct':count,'n':155})
            best=max(values,key=lambda x:(x['correct'],-abs(x['threshold']-.5),x['threshold']));save_frozen(ROOT/'evidence/compact-dev-threshold.json',{'selected':best['threshold'],'grid':values});print('Compact dev threshold frozen',best,flush=True)
    assert len(cache)==609
    save_frozen(ROOT/'results/followup-completion.json',{'calls':609,'total_calls':completion['calls']+609,'total_attempts':client.calls,'total_input_tokens':client.tokens,'total_estimated_cost_usd':client.tokens*.042/1e6,'all_index_retained':sum(meta['all_index_retained'] for _,meta in contexts.values())})
    print('Follow-up complete',client.calls,'total attempts',flush=True)

if __name__=='__main__':main()
