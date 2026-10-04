import copy,hashlib,json,unittest
from pathlib import Path
from prepare import ROOT,malware_questions,policy_questions,gates

def read(n):return json.loads((ROOT/'evidence'/n).read_text())
class EvaluationValidity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=read('malware-cases.json');cls.c=read('cloud-cases.json');cls.p=read('policy-cases.json');cls.plan=read('frozen-plan.json')
    def test_source_bytes(self):
        for r in read('malware-source-manifest.json')['records']:
            b=(ROOT.parent/r['path']).read_bytes();self.assertEqual(hashlib.sha256(b).hexdigest(),r['sha256'])
        for r in read('cloud-source-manifest.json'):
            b=(ROOT/'vendor/splunk_attack_data'/r['path']).read_bytes();self.assertEqual(hashlib.sha256(b).hexdigest(),r['sha256'])
    def test_gold_unmodified(self):
        source=read('../vendor/meta-llama_PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json')
        self.assertEqual(len(self.m),609)
        for q,s in zip(self.m,source):self.assertEqual(q['gold'],s['correct_options']);self.assertEqual(q['q'],s)
    def test_report_disjoint_split(self):
        a={q['report_id'] for q in self.m if q['split']=='dev'};b={q['report_id'] for q in self.m if q['split']=='test'}
        self.assertFalse(a&b);self.assertEqual(len(a|b),175)
        self.assertIn('e8901779b53e491d1f9f7b5406116f5927745ab46053a5f1f5c51463444ea4d9',a)
    def test_gold_never_in_request(self):
        for q in self.m:
            a=malware_questions(q['q']);poison=copy.deepcopy(q['q']);poison['correct_options']=['Z'];poison['topic']='poison';poison['difficulty']='poison';poison['attack']='poison'
            self.assertEqual(a,malware_questions(poison))
    def test_stress_and_agent_are_held_out_and_cluster_distinct(self):
        lookup={q['id']:q for q in self.m}
        for name in ('stress_ids','agent_ids'):
            items=[lookup[x] for x in self.plan['malware'][name]]
            self.assertTrue(all(q['split']=='test' for q in items));self.assertEqual(len({q['report_id'] for q in items}),len(items));self.assertEqual(len({q['family'] for q in items}),5)
    def test_context_limits(self):
        for q in self.m:
            questions=malware_questions(q['q']);state={'report_excerpts':q['contexts']['retrieved'],'unrelated_telemetry':'x'*4500}
            self.assertLess(len(json.dumps(state).encode())+max(len(json.dumps(x).encode()) for x in questions.values()),32000)
            self.assertLess(len(json.dumps({'state':state,'questions':questions}).encode()),64000)
    def test_policy_gold_against_independent_condition_table(self):
        # Explicit contract outcomes, independently enumerated rather than calling gates again.
        execute={'valid','fresh_boundary_900','receipt_queued','receipt_failed','receipt_wrong_target','receipt_old_version','receipt_missing','midnight_valid','utc_offset_valid','approval_start_boundary','fresh_boundary_zero','receipt_wrong_operation','valid_alt_id','valid_alt_time'}
        no_est={'blocked_attempt','ambiguous','remediated','untrusted_claim'}
        no_rec=no_est|{'critical','target_unknown'}
        no_completed={'version_change','injection','receipt_queued','receipt_failed','receipt_wrong_target','receipt_old_version','receipt_missing','receipt_wrong_operation'}
        for q in self.p:
            self.assertEqual(q['gold'],{'established':q['condition'] not in no_est,'recommend':q['condition'] not in no_rec,'execute':q['condition'] in execute,'completed':q['condition'] not in no_completed})
    def test_cloud_missing_actor_controls(self):
        originals={q['id']:q for q in self.c if q['variant']=='original'};self.assertEqual(len(originals),122)
        for q in self.c:
            if q['variant']=='original':continue
            self.assertIn(q['paired_original'],originals);self.assertEqual(q['questions']['actor']['criteria'][q['gold']['actor']],'UNKNOWN')
            node=q['state'];keys=q['label_paths']['actor'].split('.')
            for key in keys[:-1]:node=node[key]
            self.assertNotIn(keys[-1],node)
            self.assertEqual(q['gold']['outcome'],originals[q['paired_original']]['gold']['outcome'])
    def test_receipt_does_not_authorize(self):
        q=next(q for q in self.p if q['condition']=='missing_approval');self.assertTrue(q['gold']['completed']);self.assertFalse(q['gold']['execute'])
    def test_hashes(self):
        for name,sha in read('input-hashes.json').items():self.assertEqual(hashlib.sha256((ROOT/'evidence'/(name+'.json')).read_bytes()).hexdigest(),sha)

if __name__=='__main__':unittest.main()
