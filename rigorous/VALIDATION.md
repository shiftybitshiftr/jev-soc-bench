# Validation record

**Share with caveats** for a bounded mixed-enterprise SOC pilot-placement decision. These artifacts do not certify autonomous containment or establish production detection accuracy.

## Completed checks

- All **3,364** response records have unique request IDs, the pinned `jev-1.13.0` model and valid typed outputs. There were **3,364 attempts**, no retries and no recorded API/schema failures.
- All write-ahead reservations have matching settled entries. Stored request hashes match the exact recorded payloads. No request is silently replayed or selectively replaced with a better repeat.
- Primary frozen input and runtime code hashes still match. Public report/event source files match recorded byte hashes.
- Gold answers match the unmodified official question file. Changing gold/topic/family fields cannot change the submitted malware questions. Gold labels are not in submitted request objects.
- The malware split has **45 development reports / 155 questions** and **130 test reports / 454 questions**, with no shared report IDs. Development thresholds were written before the first held-out request timestamp.
- There are **27 identical question templates shared across splits**, appearing in **90 test questions**. The split is report-disjoint, not template-disjoint or malware-family-disjoint. Template-cluster sensitivity intervals are included; this is not a novel-task generalization test.
- Independent arithmetic using original official answers reproduces 120/454 retrieved, 75/454 prefix, 36/454 no-report and 137/454 compact exact sets. Independently tabulated policy confusion matrices match the report.
- Recorded token usage sums to **25,102,078**. At $0.042 per million input tokens, the estimate is **$1.054287276**. This is not a billing-console reconciliation or a current free-credit balance.
- Ten new validity tests and forty existing bench tests pass. The new tests include source integrity, split separation, absence of answer leakage, context limits, missing-field controls and an independently enumerated containment truth table.
- The companion notebook has four executed code cells and passes notebook-format validation. It recomputes primary scores and usage from traces without calling the API.
- Both PNG figures were opened and visually inspected. Labels, denominators, axes, intervals and values match the underlying metrics. The Markdown report and notebook are delivered as source artifacts; no claim of testing a separate interactive dashboard is made.
- Local report links resolve. The inline Sources receipt was validated and rendered by the supplied renderer.

The machine-readable independent-check record is `results/independent-validation.json`; the reproducible checker is `validate_results.py`. Primary statistics are in `analyze.py`, post-primary supplements in `finish.py` and the notebook in `analysis.ipynb`.

## Corrections and qualifications retained

1. **Parser baseline repair.** Its initial implementation scored 228/244 because Exchange detection depended on an optional UserId and omitted a Success spelling. Repairing the baseline yields 244/244; frozen labels and Jev outputs are unchanged. This repair is explicitly recorded rather than silently representing the initial implementation as perfect.
2. **Benchmark answer conventions.** Some all-of-the-above and overlapping-answer questions complicate independent per-option judgments. Primary exact-set scores are preserved. Excluding these questions is a labeled post-hoc sensitivity, not a revised headline score.
3. **Uncertain label semantics.** The Okta ALLOW mapping and several broad malware questions warrant expert adjudication. `CASE_AUDIT.md` identifies examples. No favorable relabeling was performed.
4. **Exploratory follow-ups.** Compact evidence preprocessing and identical-input repeats were designed after primary outcomes were inspected. They have separate frozen plans, traces and completion records. Their results do not replace the primary experiment or provide an untouched confirmatory holdout.
5. **Sampling uncertainty.** Cluster intervals reflect resampling the represented public reports or source datasets. They do not measure private-enterprise domain shift. A degenerate interval on an error-free narrow slice does not guarantee a perfect population rate.
6. **Construct limits.** Public enriched sandbox questions test analysis interpretation; cloud questions test exact fields; authored control fixtures test explicit policy. They cannot be pooled into one SOC accuracy rate. Repeated judgments do not become additional independent incidents.
7. **No independent human production validation.** The external malware answer set was expert reviewed by its publishers; this run did not add a second blind SOC reviewer, prospective incident outcomes or actual containment connectors.

No secret values were written to these artifacts, no malware executable was acquired or executed, and no production endpoint, identity or cloud resource was contained.
