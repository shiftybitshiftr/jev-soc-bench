# Validation notes

These checks cover the recorded October 4, 2026 evaluation. Run `python scripts/check.py` from the repository root to repeat the local checks without calling Jev.

## Data and traces

- All 3,364 responses have unique request IDs, model `jev-1.13.0` and valid typed outputs. The ledger records 3,364 attempts, no retries and no API or schema failures.
- Every write-ahead reservation has a matching settled entry. Payload hashes match the recorded requests; primary input, runtime and source hashes also match.
- Labels match the published question file. Labels, topics and family metadata are excluded from submitted malware questions.
- Development used 45 reports and 155 questions; test used 130 reports and 454 questions. No report IDs overlap. Development thresholds were saved before the first test request.
- The split does share 27 question templates, covering 90 test questions. It is not a test of new templates or unseen malware families. Template-cluster sensitivity intervals are saved alongside report-cluster intervals.

## Calculations

Independent arithmetic from the original answers reproduces 120/454 retrieved, 75/454 prefix, 36/454 no-report and 137/454 compact answer sets. Separately tabulated policy confusion matrices match the report.

Recorded usage sums to 25,102,078 input tokens. At the run's rate of $0.042 per million input tokens, that is $1.054287276. This estimate has not been reconciled with account billing.

The original run passed 40 bench tests and 10 evaluation-validity tests. The repository also has setup-integrity tests. The notebook's four code cells recompute scores and usage from traces, and the notebook passes format validation. Figure labels, axes, intervals and values were checked against the metrics.

The saved check record is [independent-validation.json](results/independent-validation.json). Repeating [validate_results.py](validate_results.py) in this checkout writes an ignored `results/repository-validation.json` without replacing the original record. Analysis lives in [analyze.py](analyze.py), with recorded follow-ups in [finish.py](finish.py).

## Corrections and limitations

The parser baseline initially scored 228/244. Exchange detection incorrectly depended on an optional `UserId`, and outcome handling omitted the `Success` spelling. Fixing those bugs brought it to 244/244. Jev responses and labels were unchanged.

The Okta `ALLOW` label and several broad malware questions need expert adjudication. Examples are in [CASE_AUDIT.md](CASE_AUDIT.md). Published labels were retained; excluding “all/none of the above” questions is a separate sensitivity analysis.

Compact evidence and identical-input repeats were added after inspecting primary results. They have separate plans, traces and completion records. The compact result is exploratory, even though it reuses the original test split.

Intervals describe variation among the sampled public reports or source datasets. They do not account for differences from private enterprise alerts. An error-free slice does not imply a zero population error rate, and repeated calls do not add independent incidents.

The source publishers supplied expert-reviewed malware labels. This run added no blind human adjudication, prospective incident outcomes or real containment connectors. It measures three separate tasks: interpreting enriched reports, extracting exact event fields and following authored policy contracts.
