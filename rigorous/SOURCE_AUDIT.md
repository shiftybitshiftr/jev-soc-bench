# Source fitness and exclusions

| Source | Acquired material | Use and limitation |
|---|---|---|
| CrowdStrike / Meta CyberSOCEval | 175 public sandbox JSON reports, 609 unchanged expert-reviewed questions | Main behavior-interpretation task. Reports contain prior security enrichment; public training contamination is unknown. Multiple questions share reports and templates. |
| Splunk attack_data | 122 JSON event records from eight Azure, Okta and Exchange datasets | Exact actor/type/outcome extraction. Repository membership is not a maliciousness label. The additional 122 missing-actor cases are authored paired transformations. |
| Authored response contracts | Eight incident templates × 32 controlled conditions | Exact policy and temporal/version boundary tests. Expected outcomes come from executable rules and an independently enumerated condition table, not real incident adjudication. |
| SOCBench | 757,641 flow rows from eight captures | Audited and excluded from primary scoring due to collection artifacts. |
| OTRF / CyberSOCEval CTI discovery | Repository trees, documentation and the CTI question bank | Explored during source selection; not scored and not counted as evaluation coverage. |

## Why network flow scores are not presented

`evidence/network-audit.json` records the audit of the pinned SOCBench parquet. There are no exact duplicate rows. However, all **27,524** rows from the four normal captures have protocol `unknown`, missing inbound packet counts and missing outbound packet counts. The four malware captures contain both benign and attack-labeled traffic, use known numeric protocols and have no missing inbound packet counts. Their timestamp eras also differ from most normal captures. The largest capture contains 632,787 rows, so random-row splitting would heavily reuse one collection context.

These artifacts would make a random-row accuracy result hard to interpret. Removing the visible shortcuts would not automatically remove the broader capture/domain confounding. No model result from this corpus is used to recommend Jev for production detection or compared against the SOCBench leaderboard.

## Provenance and units

Repository commits, source URLs, sizes and content hashes are retained in `evidence/*source-manifest.json` and the root `data-sources.json`. Every malware test question is linked to a report hash. Every cloud case identifies its source file, original line and label JSON paths. Paired removal controls identify their original case. Every model trace records the exact submitted state and typed questions.

The independent units for malware inference are report clusters, with question-template sensitivity checks. Agent and stress results are paired on 60 distinct test reports. Cloud uncertainty is limited by eight source datasets; the policy suite is a fixed set of eight authored templates. Neither additional variants nor numeric answer fields increase the independent incident count.
