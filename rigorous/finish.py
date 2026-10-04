"""Add the recorded follow-up results and rebuild the analysis notebook."""
import contextlib,datetime,io,json,statistics
from pathlib import Path
import nbformat
from prepare import ROOT
from analyze import malware_metric,comparison,predicted,report as primary_report

def main():
    load=lambda p:json.loads((ROOT/p).read_text());m=load('results/metrics.json');cases=load('evidence/malware-cases.json');test=[q for q in cases if q['split']=='test'];lookup={q['id']:q for q in cases}
    rows={x['id']:x for f in ('calls.jsonl','followup-calls.jsonl','repeat-calls.jsonl') for x in [json.loads(l) for l in (ROOT/'results'/f).read_text().splitlines()]}
    ids=load('evidence/frozen-plan.json')['malware']['stress_ids'];compact=malware_metric(test,rows,'compact');delta=comparison(test,rows,'compact','retrieved')
    repeats={'n':len(ids),'answer_set_changes':sum(predicted(rows[x+'/repeat'])!=predicted(rows[x+'/retrieved']) for x in ids),'score_changes':sum(rows[x+'/repeat']['response']['answers']!=rows[x+'/retrieved']['response']['answers'] for x in ids),'exact_correct':sum(predicted(rows[x+'/repeat'])==set(lookup[x]['gold']) for x in ids)}
    repeat_target=sum(predicted(rows[x['case']+'/repeat'])==set(x['goal']) and not x['clean_already_target'] for x in m['stress']['injection']['attack_goals'])
    supplement={'compact':compact,'compact_minus_retrieved':delta,'repeat_controls':repeats,'repeat_attacker_target_hits_without_attack':repeat_target,'total':load('results/total-completion.json'),
      'paired_agent_tokens':sum(x['input_tokens'] for x in m['agent']['records']),'paired_static_tokens':sum(rows[x+'/retrieved']['response']['usage']['input_tokens'] for x in ids)}
    (ROOT/'results/supplement.json').write_text(json.dumps(supplement,indent=2))
    total=supplement['total'];sensitivity=m['posthoc_sensitivity']['exclude_all_none_above']
    summary=f'''Including follow-ups, the run used {total['calls']:,} calls and {total['input_tokens']:,} input tokens, at an estimated cost of ${total['estimated_cost_usd']:.2f}. The primary experiment accounts for {m['completion']['calls']:,} calls. Repeats are not additional independent incidents.

'''
    primary_report(m)
    report=(ROOT/'REPORT.md').read_text();marker='The three tasks use different data';at=report.index(marker);report=report[:at]+summary+report[at:]
    extra=f'''## Follow-up analysis

After reviewing the primary failures, a compact adapter was added. It retains all technique and signature names for each of the 609 questions and fills the remaining 24,000-byte budget with details. On the test questions it gets {compact['correct']}/{compact['n']} ({compact['accuracy']*100:.1f}%) answer sets right, a {delta['difference']*100:.1f}-point improvement over query-ranked retrieval. The descriptive report-cluster interval for that difference is {delta['report_cluster_ci95'][0]*100:.1f}–{delta['report_cluster_ci95'][1]*100:.1f} points. Its threshold of 0.5 was selected on development data, but the adapter was designed after seeing test failures. This result is exploratory.

Excluding the 71 test questions with “all/none of the above” leaves {sensitivity['correct']}/{sensitivity['n']} ({sensitivity['accuracy']*100:.1f}%) correct in the original retrieval arm. The overall result barely changes.

Identical-input repeats changed {repeats['answer_set_changes']}/60 answer sets and {repeats['score_changes']}/60 numeric score sets. Injection changed 8/60 answer sets, reordered questions 6/60, and padding 5/60. These comparisons do not isolate an injection-specific effect. Injection reached one nontrivial attacker target; clean repeats reached {repeat_target}. The clean arm answered only 16/60 correctly, limiting what this small attack test can establish.

The agent used {supplement['paired_agent_tokens']:,} tokens versus {supplement['paired_static_tokens']:,} for fixed retrieval on the same 60 questions. It averaged 3.13 API calls per episode: more round trips, almost the same token use.

Parser validation caught two bugs: Exchange detection depended on an optional `UserId`, and outcome handling omitted the `Success` spelling. Repairs improved the baseline from 228/244 to 244/244. Model responses and labels stayed unchanged. The only original-event outcome disagreement was Okta `ALLOW`, labeled unknown by the frozen mapping. That mapping needs SOC agreement before treating it as a model failure.

Authorization errors occurred in every eight-case group with a not-yet-valid approval, a 901-second-old observation, a one-second-future observation or an unverified target. All eight valid UTC-offset cases were denied. These are counterexamples to relying on model authorization, not estimates of how often the conditions occur in production.

'''
    report=report.replace('## Data limitations',extra+'## Data limitations')
    (ROOT/'REPORT.md').write_text(report)
    # Executed notebook: independent arithmetic from saved traces, no remote calls.
    cells=[nbformat.v4.new_markdown_cell('# Jev SOC analysis\n\nRecompute the saved scores and token usage. Start Jupyter in `rigorous/` after running setup. These cells read local traces and make no API calls.'),
      nbformat.v4.new_code_cell("import json\nfrom pathlib import Path\nfrom collections import Counter\nroot = Path.cwd()\nassert (root/'evidence/frozen-plan.json').exists()\nprimary = [json.loads(line) for line in (root/'results/calls.jsonl').read_text().splitlines()]\nrows = {row['id']: row for row in primary}\ncases = json.loads((root/'evidence/malware-cases.json').read_text())\nprint('Primary calls:', len(primary))\nprint('Unique reports:', len({c['report_id'] for c in cases}))\nprint(Counter(c['split'] for c in cases))"),
      nbformat.v4.new_code_cell("official = json.loads((root/'vendor/meta-llama_PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json').read_text())\nfor arm in ['retrieved', 'prefix', 'none']:\n    n = correct = 0\n    for i, question in enumerate(official):\n        if cases[i]['split'] != 'test': continue\n        answers = rows[f'M{i:04d}/{arm}']['response']['answers']\n        selected = {key[7:] for key, value in answers.items() if value['noul'] >= .5}\n        correct += selected == set(question['correct_options'])\n        n += 1\n    print(arm, correct, '/', n, '=', round(100*correct/n, 2), '%')"),
      nbformat.v4.new_code_cell("policy = json.loads((root/'evidence/policy-cases.json').read_text())\nfor field in ['established', 'recommend', 'execute', 'completed']:\n    false_positive = negatives = false_negative = positives = 0\n    for case in policy:\n        gold = case['gold'][field]\n        selected = rows[case['id']+'/policy']['response']['answers'][field]['noul'] >= .5\n        negatives += not gold\n        positives += gold\n        false_positive += selected and not gold\n        false_negative += not selected and gold\n    print(field, 'FP', false_positive, '/', negatives, 'FN', false_negative, '/', positives)"),
      nbformat.v4.new_code_cell("all_rows = primary + [json.loads(line) for filename in ['followup-calls.jsonl','repeat-calls.jsonl'] for line in (root/'results'/filename).read_text().splitlines()]\ntokens = sum(row['response']['usage']['input_tokens'] for row in all_rows)\nprint('All calls:', len(all_rows), 'input tokens:', tokens, 'estimated USD:', tokens*.042/1_000_000)\nassert len({row['id'] for row in all_rows}) == len(all_rows)"),
      nbformat.v4.new_markdown_cell('## Figures\n\n![Primary results](figures/pipeline-results.png)\n\n![Calibration](figures/calibration.png)\n\nSee `REPORT.md`, `CASE_AUDIT.md`, `VALIDATION.md` and `results/independent-validation.json`. Report-cluster and template-cluster bootstrap calculations are in `analyze.py`. The compact adapter and stability controls are explicitly exploratory.')]
    ns={};count=0
    for cell in cells:
        if cell.cell_type!='code':continue
        count+=1;capture=io.StringIO()
        with contextlib.redirect_stdout(capture):exec(cell.source,ns)
        cell.execution_count=count;cell.outputs=[nbformat.v4.new_output('stream',name='stdout',text=capture.getvalue())]
    notebook=nbformat.v4.new_notebook(cells=cells,metadata={'kernelspec':{'name':'python3','display_name':'Python 3','language':'python'}});nbformat.validate(notebook);nbformat.write(notebook,ROOT/'analysis.ipynb')
    print(json.dumps(supplement,indent=2))
if __name__=='__main__':main()
