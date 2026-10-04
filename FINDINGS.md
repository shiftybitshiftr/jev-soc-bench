# Jev SOC evaluation

Jev did well on small, explicit judgments and struggled with broader evidence interpretation. Its best candidate role is answering a narrow question about evidence that has already been selected and checked. Identity resolution, approval checks and action verification belong in code. The results give little reason to let Jev run an investigation or authorize containment on its own.

Tested October 4, 2026 with `jev-1.13.0`: 3,364 successful calls, 25.1 million input tokens and about $1.05 in estimated inference cost. Calls include repeated trials and follow-ups; they are not independent incidents.

## Evidence interpretation

The main test used 454 questions from 130 sandbox reports held out from development. A question counted as correct only if the entire selected answer set matched the published labels.

| Input | Correct answer sets |
|---|---:|
| Query-ranked report excerpts | 120/454 (26.4%) |
| Source-order excerpts | 75/454 (16.5%) |
| No report | 36/454 (7.9%) |
| TF-IDF option matching | 13/454 (2.9%) |
| Compact evidence index, added after the primary run | 137/454 (30.2%) |

Retrieval helped by 18.5 percentage points over the no-report baseline, but still left nearly three quarters of answer sets wrong. The 95% interval for retrieval accuracy was 22.6–30.3%, resampling whole reports.

![Evidence accuracy and containment errors](rigorous/figures/pipeline-results.png)

The left panel measures performance on public benchmark questions. The right counts errors in authored policy cases. They have different denominators and should not be averaged.

Some failures came from missing evidence; others missed facts already present in the prompt. Keeping all technique and signature names in a compact index added 3.7 points. That adapter was built after reviewing failures, so its result needs confirmation on new data. Removing 71 “all/none of the above” questions left accuracy at 26.4%. Answer conventions complicate individual cases but do not explain the overall result. See the [case audit](rigorous/CASE_AUDIT.md).

## Cloud identities

Jev got the event type right in all 122 original cloud records and the actor ID right in 118. When the authoritative actor field was removed, it selected another identifier in 54/122 cases instead of returning UNKNOWN. Fourteen of those wrong choices had reported confidence of at least 0.8.

A schema parser got all three requested fields right in 244/244 original and modified records after two implementation bugs were fixed. For known schemas, a parser is the better fit. A plausible tenant, application or object ID is not evidence of who initiated an event.

## Containment

These were 256 authored cases: eight incident templates with 32 conditions each. They tested explicit contracts, including stale evidence, missing approvals, wrong targets and execution receipts.

| Decision | Jev result |
|---|---:|
| Compromise established | 256/256 correct |
| Recommend containment | 248/256 correct; 8 unsupported recommendations |
| Authorize action | 42/144 invalid requests approved; 16/112 valid requests denied |
| Action completed | 253/256 correct; 3 completions missed |

All eight unverified targets received containment recommendations. Authorization failed every eight-case group with an approval one second in the future, evidence one second in the future, or evidence 901 seconds old against a 900-second limit. It also denied all eight valid UTC-offset cases.

Raising the authorization threshold from 0.5 to 0.8 still left 30 invalid approvals and increased missed valid approvals to 30. Combining Jev's compromise judgment with code that enforced the remaining policy produced 256/256 correct authorization decisions. That shows the checks work on these fixtures; it does not estimate a production false-containment rate.

## Investigation and confidence

The agent answered 12/60 questions correctly, versus 16/60 with fixed retrieval. The paired difference was −6.7 points, with a 95% interval of −18.3 to +5.0: too uncertain to establish an advantage either way. It averaged 2.13 tool reads and 3.13 API calls per episode. Token use was almost identical: 704,621 versus 703,178.

![Confidence calibration](rigorous/figures/calibration.png)

Requiring binary confidence of at least 0.8 for every option accepted just 28/454 questions; 22/28 were exactly correct. Confidence filtering discarded most questions and still let errors through.

Identical-input repeats changed 7/60 answer sets, compared with 8/60 under prompt injection. With that instability, a weak clean baseline and only six attack templates, these tests cannot establish broad injection resistance or attribute every changed answer to the attack.

## Where to use it

A supervised trial of narrow semantic judgments is worth testing. Parse identities and timestamps first, retrieve the relevant evidence, then ask Jev a specific question. Enforce target, approval, freshness and version checks in code. Require analyst approval and verify actions through connector receipts.

Speed and price make this plausible: primary calls took 170 ms median and 240 ms p95 at the client. Those timings exclude retrieval and SOC connectors. This evaluation did not measure analyst time saved or compare a stronger model on the same inputs.

The main limitations are in the data. Sandbox reports already contain signatures, AV verdicts and MITRE annotations. Public training-data exposure is unknown. Reports were split between development and test, but question templates overlap. Cloud records came from eight datasets; containment cases were authored. The [source audit](rigorous/SOURCE_AUDIT.md) also explains why network flows were excluded for collection artifacts.

Before deployment, the missing evidence is a private, time-separated alert set at the actual alert base rate, adjudicated by two SOC reviewers, followed by a shadow trial. Compare Jev with rules alone and a stronger model on identical evidence. Measure missed incidents, incorrect target IDs, false containment, analyst time and accuracy as the system abstains more often.

The [full report](rigorous/REPORT.md) has thresholds, intervals and per-topic results. [Validation](rigorous/VALIDATION.md) records checks of all 3,364 responses; [metrics](rigorous/results/metrics.json) and the [notebook](rigorous/analysis.ipynb) contain the supporting calculations.
