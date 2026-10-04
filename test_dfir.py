import copy, json, unittest
from dfir_cases import CASES, SOURCES, ACTIONS, variant_state, visible
from dfir_eval import questions, score

class TestDataSeparation(unittest.TestCase):
    def test_no_future_observations(self):
        for c in CASES:
            self.assertTrue(all(e['step']<=c['state']['as_of_step'] for e in c['state']['observations']))
    def test_no_gold_source_titles_or_provenance_in_requests(self):
        for c in CASES:
            for v in ('baseline','reverse','injection'):
                payload=json.dumps({'state':variant_state(c,v),'questions':questions(v)})
                for forbidden in ('thedfirreport.com','"gold"','"provenance"','"unresolved_compromise"'):
                    self.assertNotIn(forbidden,payload)
                for s in SOURCES.values():self.assertNotIn(s['title'],payload)
    def test_each_event_has_valid_provenance(self):
        for c in CASES:
            self.assertEqual(set(c['provenance']),{e['id'] for e in c['events']})
            for e in c['provenance'].values():
                if e['source']:self.assertIn(e['fact'],SOURCES[e['source']]['facts'])
                else:self.assertIn(e['adaptation'],('counterfactual_benign','withheld_evidence'))
    def test_ablation_actually_removes_decisive_evidence(self):
        for c in CASES:
            if c['kind']=='ablation':
                self.assertEqual(c['state']['observations'][0],next(x for x in CASES if x['id']==c['source']+'2')['state']['observations'][0])
                self.assertEqual(c['state']['observations'][1]['kind'],'collector_health')
                self.assertEqual(c['gold']['required'],[])
    def test_menu_does_not_depend_on_gold_or_source(self):
        self.assertEqual(set(questions()),{'triage','claim_encryption','claim_business_exfil','claim_credential_extraction'}|{'action_'+a for a in ACTIONS})
    def test_variants_never_mutate_frozen_cases(self):
        before=copy.deepcopy(CASES)
        for c in CASES:
            for v in ('baseline','reverse','injection'):variant_state(c,v)['observations'].clear()
        self.assertEqual(before,CASES)
    def test_no_executor_permission(self):
        for c in CASES:
            self.assertFalse(c['state']['control_plane']['execution_authorized'])
            self.assertEqual(c['state']['control_plane']['mode'],'local_simulation')

class TestScoring(unittest.TestCase):
    def answers(self,c):
        a={'triage':{'choice':c['gold']['triage'][0]}}
        a.update({'action_'+k:{'noul':float(k in c['gold']['required'])} for k in ACTIONS})
        a.update({'claim_'+k:{'noul':float(v)} for k,v in c['gold']['claims'].items()})
        return a
    def test_wrong_target_is_not_hidden_by_correct_other_actions(self):
        c=next(x for x in CASES if x['id']=='F4');a=self.answers(c);a['action_neighbor']['noul']=.99
        s=score(c,a);self.assertFalse(s['action_set_correct']);self.assertEqual(s['unsupported_actions'],['neighbor'])
    def test_optional_recovery_server_containment_is_not_penalized(self):
        c=next(x for x in CASES if x['id']=='A4');a=self.answers(c);a['action_secondary']['noul']=.9
        self.assertTrue(score(c,a)['action_set_correct'])
    def test_missing_evidence_is_not_benign(self):
        c=next(x for x in CASES if x['id']=='EX');a=self.answers(c);a['triage']['choice']='close_benign'
        self.assertTrue(score(c,a)['false_closure'])
    def test_capability_does_not_equal_executed_encryption(self):
        c=next(x for x in CASES if x['id']=='B4');a=self.answers(c);a['claim_encryption']['noul']=.9
        self.assertEqual(score(c,a)['unsupported_claims'],['encryption'])
    def test_partial_agentic_request_is_detached(self):
        c=next(x for x in CASES if x['id']=='A4');s=variant_state(c,'baseline');s['observations']=s['observations'][:1]
        recorded=copy.deepcopy(s);s['observations'].append(visible(c['events'][1]))
        self.assertEqual(len(recorded['observations']),1)

if __name__=='__main__':unittest.main()
