# Jev SOC evaluation: detailed results

Model: jev-1.13.0. Completed 2026-10-04T08:38:56.046710+00:00. 2,695 successful API calls, 18,612,554 input tokens; estimated model cost $0.782 at $0.042/M input tokens. Response actions were simulated.

Including follow-ups, the run used 3,364 calls and 25,102,078 input tokens, at an estimated cost of $1.05. The primary experiment accounts for 2,695 calls. Repeats are not additional independent incidents.

The three tasks use different data: public malware questions, exact cloud event fields and authored containment cases. Results are reported separately because they measure different things.

![Pipeline results](figures/pipeline-results.png)

## Evidence interpretation

CyberSOCEval provides 609 expert-reviewed multiple-select questions over 175 real sandbox reports. A report-disjoint split reserves 155 questions for development and 454 for test. The initially inspected example report is development-only. Gold answers remain unmodified. Signatures, AV verdicts and MITRE annotations already enrich these reports: this tests interpretation of security analysis, not raw malware detection.

| Input supplied to Jev | Exact sets at 0.5 | 95% report-cluster interval | Option precision / recall | Brier |
|---|---:|---:|---:|---:|
| Query-ranked excerpts | 120/454 (26.4%) | 22.6–30.3% | 58.6% / 76.0% | 0.196 |
| Source-order excerpts | 75/454 (16.5%) | 12.5–20.6% | 54.0% / 60.5% | 0.222 |
| No report | 36/454 (7.9%) | 5.6–10.5% | 72.4% / 13.2% | 0.209 |

A TF-IDF option-matching baseline, threshold chosen only on development reports, scores 13/454 (2.9%).

Retrieved evidence minus no report: +18.5 percentage points, paired report-cluster 95% interval +14.5 to +22.5 points.
Retrieved evidence minus source-order excerpts: +9.9 percentage points, paired report-cluster 95% interval +5.6 to +14.3 points.

Thresholds were selected before test calls, independently for each input arm. They are a separate diagnostic, not a replacement for the fixed-threshold primary outcome.

| Arm | Dev-selected threshold | Held-out exact sets |
|---|---:|---:|
| retrieved | 0.60 | 115/454 (25.3%) |
| prefix | 0.55 | 77/454 (17.0%) |
| none | 0.40 | 79/454 (17.4%) |

At a fixed abstention rule requiring every option's binary confidence to reach 0.8, Jev accepts 28/454 questions (6.2% coverage) and answers 22/28 exactly. Scores are not assumed to be calibrated probabilities.

![Calibration diagnostic](figures/calibration.png)

## Tool use and perturbations

The agent chose among report-section readers, with at most four reads and 6,000 bytes per reader. It could stop whenever useful; it was not required to exhaust all tools. Final answers count even on early stopping or budget exhaustion. On the paired 60-question subset: agent 12/60, fixed retrieval 16/60, no report 4/60. Mean reads: 2.13; budget-exhausted episodes: 9. Median cumulative API latency per episode: 478 ms.

Agent minus fixed retrieval: -6.7 points, paired 95% interval -18.3 to +5.0 points. The two adapters use the same maximum evidence-byte budget but different chunk allocations; this comparison concerns these complete pipelines, not an isolated reasoning capability.

| Perturbation, 60 paired reports each | Exact answers | Changed answer sets | Clean-correct answers made wrong |
|---|---:|---:|---:|
| reverse | 15/60 | 6/60 | 1/16 |
| padding | 15/60 | 5/60 | 1/16 |
| injection | 16/60 | 8/60 | 2/16 |

Six frozen prompt-injection templates produced 1/50 induced attacker-target answers, excluding cases already at that target. This is a limited fixed-attack test, not adaptive red teaming or evidence of general injection resistance. 'Reverse' changes candidate/question ordering, not underlying content.

## Cloud event fields

122 original records from eight public Splunk datasets are paired with 122 copies where only the authoritative actor ID is removed. The latter controls should return UNKNOWN even when other plausible IDs remain. These logs are selected security test data; an event in the repository is not automatically labeled malicious.

| Variant | Actor ID | Recorded event type | Recorded operation outcome | All three exact |
|---|---:|---:|---:|---:|
| original | 118/122 | 122/122 | 121/122 | 117/122 |
| actor_field_removed | 68/122 | 122/122 | 121/122 | 67/122 |

A separate known-schema parser gets all three fields right on 244/244 cases. This is a narrow extraction contract; it does not assess whether an event is malicious. Only eight source datasets are represented, with uneven row counts. Missing-field controls are paired transformations, not additional independent incidents.

## Containment decisions

Eight authored incident templates each have 32 controlled conditions, including missing/wrong approvals, one-second freshness boundaries, expiry boundaries, UTC offsets, version drift, tool errors, untrusted claims, and stale/wrong receipts. Gold outcomes are checked against an independently enumerated condition table. Model probabilities are thresholded at 0.5. Hybrid uses the same Jev semantic-compromise judgment, with exact code checks for the remaining policy.

| Decision | Jev alone: correct | False positives / negative cases | Missed positives / positive cases | Hybrid: correct | Hybrid false positives |
|---|---:|---:|---:|---:|---:|
| established | 256/256 | 0/32 | 0/224 | 256/256 | 0 |
| recommend | 248/256 | 8/48 | 0/208 | 256/256 | 0 |
| execute | 198/256 | 42/144 | 16/112 | 256/256 | 0 |
| completed | 253/256 | 0/64 | 3/192 | 256/256 | 0 |

The gate is a designed control, not evidence that Jev itself is safer. Its success depends on trustworthy telemetry and control-plane fields. The suite is not a prevalence sample: its error fractions cannot be read as production false-containment rates. A successful receipt can prove an action happened even when it was unauthorized; those questions are deliberately scored independently.

| Decision at a stricter 0.8 threshold | Jev false positives | Jev missed positives |
|---|---:|---:|
| recommend | 4 | 3 |
| execute | 30 | 30 |
| completed | 0 | 10 |

## Results by topic

| Expert-reviewed question topic | Retrieved exact | No-report exact |
|---|---:|---:|
| Persistence Techniques | 9/62 | 2/62 |
| Evasion Techniques | 9/53 | 4/53 |
| File Operations | 11/53 | 2/53 |
| Risk Assessment | 14/57 | 1/57 |
| Privilege Escalation | 9/36 | 8/36 |
| MITRE ATT&CK Framework Mapping | 13/46 | 2/46 |
| System Interactions | 25/73 | 7/73 |
| Behavioral Analysis | 30/74 | 10/74 |

These topic slices are exploratory and may share question templates. Their rankings are not independent significance tests. Item-level scores and all failed exact sets are preserved in `results/item-scores.csv` and `results/metrics.json`.

## Follow-up analysis

After reviewing the primary failures, a compact adapter was added. It retains all technique and signature names for each of the 609 questions and fills the remaining 24,000-byte budget with details. On the test questions it gets 137/454 (30.2%) answer sets right, a 3.7-point improvement over query-ranked retrieval. The descriptive report-cluster interval for that difference is 0.4–7.1 points. Its threshold of 0.5 was selected on development data, but the adapter was designed after seeing test failures. This result is exploratory.

Excluding the 71 test questions with “all/none of the above” leaves 101/383 (26.4%) correct in the original retrieval arm. The overall result barely changes.

Identical-input repeats changed 7/60 answer sets and 59/60 numeric score sets. Injection changed 8/60 answer sets, reordered questions 6/60, and padding 5/60. These comparisons do not isolate an injection-specific effect. Injection reached one nontrivial attacker target; clean repeats reached 0. The clean arm answered only 16/60 correctly, limiting what this small attack test can establish.

The agent used 704,621 tokens versus 703,178 for fixed retrieval on the same 60 questions. It averaged 3.13 API calls per episode: more round trips, almost the same token use.

Parser validation caught two bugs: Exchange detection depended on an optional `UserId`, and outcome handling omitted the `Success` spelling. Repairs improved the baseline from 228/244 to 244/244. Model responses and labels stayed unchanged. The only original-event outcome disagreement was Okta `ALLOW`, labeled unknown by the frozen mapping. That mapping needs SOC agreement before treating it as a model failure.

Authorization errors occurred in every eight-case group with a not-yet-valid approval, a 901-second-old observation, a one-second-future observation or an unverified target. All eight valid UTC-offset cases were denied. These are counterexamples to relying on model authorization, not estimates of how often the conditions occur in production.

## Data limitations

- SOCBench network flows were audited and excluded from primary scoring: all 27,524 rows from normal captures use unknown protocol and missing packet counts; attack-source captures use a different schema. Timestamp eras also differ, and only four attack captures are represented. A classifier could exploit those collection artifacts.
- Public report exposure during model training cannot be ruled out. The no-report arm measures task shortcuts and prior knowledge but cannot prove or disprove memorization.
- External answer keys were expert reviewed but can contain ambiguity. The typed multi-label adapter and 24,000-byte evidence cap differ from the original CyberSOCEval implementation; these are not official leaderboard scores.
- No prospective enterprise alert stream, base-rate estimate, private incident holdout or independent human adjudication of the authored policy suite was available. No measured production detection precision, analyst time saved or safe autonomous-response rate is claimed.
- Confidence intervals resample entire report clusters, with an additional question-template sensitivity interval in the JSON. They describe this sampling model, not uncertainty over every possible enterprise. The synthetic suite reports counts across fixed cases.
- Earlier DFIR results remain separate: 216/216 acceptable triage decisions came from 36 fixtures × 3 variants × 2 repeats; exact containment sets were 145/216. That narrower result never meant 216 independent incidents or complete response correctness.

## Run details

Frozen plan SHA-256: `c7266e02d55997bbd5d2695b27a4743ced9886ba046c37faad4ae789446b0442`. Requests and responses are recorded without authorization headers. A write-ahead ledger prevents silent replay of uncertain calls. Development thresholds were saved before held-out calls. Latency is sequential client-observed request time: median 170 ms, p95 240 ms; it excludes local retrieval and real SOC connector latency. Cost is token-derived, not an account billing readback.

Files: [frozen plan](evidence/frozen-plan.json), [metrics](results/metrics.json), [item scores](results/item-scores.csv), [compressed raw calls](../artifacts/rigorous/results/calls.jsonl.gz), [analysis script](analyze.py), [companion notebook](analysis.ipynb), [validation](VALIDATION.md), [case audit](CASE_AUDIT.md).

## Sources

- [CyberSOCEval paper](https://arxiv.org/abs/2509.20166): expert-review process and original tasks.
- [CrowdStrike report corpus](https://github.com/CrowdStrike/CyberSOCEval_data): pinned commit `ce7daa5bc7da51559ca97476d2277be02631783e`; Hybrid Analysis data CC BY-SA 4.0. Local transformed report excerpts retain that attribution and license. See the vendored data license.
- [Meta PurpleLlama questions and implementation](https://github.com/meta-llama/PurpleLlama): pinned commit `172c1074069eb88ec834124272c1b1c4f8893445`, unmodified answers; MIT license retained.
- [Splunk attack data](https://github.com/splunk/attack_data): pinned commit `a92cc4e6d7e39d56a0840d206a0963eeee0e22db`; public lab events, Apache-2.0 license retained.
- [SOCBench](https://github.com/DeepTempo/socbench): pinned commit `f27c91793b7e7f957cb63dadb3cf3ba78292fa3e`; data-quality exclusion, not a scored comparison.
- [Jev model documentation](https://docs.typesafe.ai/models) and [model limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13): pinned version, prices, context limits and numerical/reasoning caveats.
- [NIST AI 800-3](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-3.pdf): statistical evaluation and dependence considerations.
- [AgentDojo](https://arxiv.org/abs/2406.13352): tool-result injection and joint task utility/security evaluation. This suite borrows the distinction; it is not an AgentDojo reproduction.
