"""Identical-input controls for the 60 paired robustness cases; no answer resampling selection."""
import datetime,hashlib,json,sys
from pathlib import Path
from prepare import ROOT,malware_questions,save_frozen
sys.path.insert(0,str(ROOT.parent))
from bench import Client

def main():
    base=json.loads((ROOT/'results/followup-completion.json').read_text());plan=json.loads((ROOT/'evidence/frozen-plan.json').read_text());cases={q['id']:q for q in json.loads((ROOT/'evidence/malware-cases.json').read_text())}
    save_frozen(ROOT/'evidence/repeat-control-plan.json',{'case_ids':plan['malware']['stress_ids'],'reason':'Post-primary identical-input stability control to avoid attributing ordinary answer variation to prompt injection. All repeats retained; never pick the best answer.','model':'jev-1.13.0','code_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    path=ROOT/'results/repeat-calls.jsonl';old=[json.loads(x) for x in path.read_text().splitlines()] if path.exists() else [];cache={r['id']:r for r in old};assert len(cache)==len(old)
    ledger_path=ROOT/'results/repeat-ledger.jsonl';journal=[json.loads(x) for x in ledger_path.read_text().splitlines()] if ledger_path.exists() else [];assert {x['id'] for x in journal if x['event']=='reserve'}=={x['id'] for x in journal if x['event']=='settled'}
    client=Client(max_calls=3500,max_input_tokens=35000000);client.calls=base['total_attempts']+sum(r['attempts'] for r in old);client.tokens=base['total_input_tokens']+sum(r['response']['usage']['input_tokens'] for r in old)
    with path.open('a') as f,ledger_path.open('a') as journal:
        for id in plan['malware']['stress_ids']:
            key=id+'/repeat'
            if key in cache:continue
            q=cases[id];journal.write(json.dumps({'event':'reserve','id':key})+'\n');journal.flush()
            row={'id':key,'case':id,'arm':'repeat','utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};row.update(client.ask({'report_excerpts':q['contexts']['retrieved']},malware_questions(q['q'])))
            f.write(json.dumps(row)+'\n');f.flush();journal.write(json.dumps({'event':'settled','id':key})+'\n');journal.flush();cache[key]=row
    save_frozen(ROOT/'results/total-completion.json',{'calls':base['total_calls']+len(cache),'attempts':client.calls,'input_tokens':client.tokens,'estimated_cost_usd':client.tokens*.042/1e6,'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print('Stability controls complete',len(cache),'total calls',client.calls,flush=True)
if __name__=='__main__':main()
