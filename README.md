# Jev SOC bench

A local harness for testing Jev on security evidence, cloud event fields and containment decisions. It uses the hosted Jev API; response actions are simulated.

[Findings](FINDINGS.md) covers the October 2026 evaluation: 3,364 calls, the main failures, and where Jev might fit in a SOC. The [full report](rigorous/REPORT.md) has the detailed results and methods.

## Setup

Use Python 3.9–3.12. CI runs on 3.11.

```sh
git clone https://github.com/shiftybitshiftr/jev-soc-bench.git
cd jev-soc-bench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/setup_data.py
python scripts/check.py
```

Setup restores the saved traces and downloads about 33 MB of public source data, checking each file against its recorded size and SHA-256. It needs no API key. Use `--offline` to restore only the bundled traces, or skip setup entirely to read the findings.

## Run

Set `TYPESAFE_API_KEY` in your environment through your secret manager, then:

```sh
python scripts/new_run.py --output runs/my-eval --execute
```

Omit `--execute` to stage a run without calling Jev. Each run requires a new output directory. Its primary report, metrics and request/response traces go under `runs/my-eval/rigorous/`.

The suite pins `jev-1.13.0` and caps usage at 3,500 API attempts and 35 million input tokens. The recorded run cost about $1.05 at the October 2026 rate; the token cap corresponds to $1.47 at that rate. Check current pricing before running.

Add `--followups` to run the compact-evidence experiment and identical-input repeats. Their traces and combined usage are saved separately; the generated primary report does not score them.

Keep API keys out of command arguments, files and notebooks. New runs, downloaded data and expanded traces are ignored by Git.

## Inspect the saved run

- [Case audit](rigorous/CASE_AUDIT.md): examples of retrieval failures, model errors and ambiguous labels.
- [Validation](rigorous/VALIDATION.md): checks on the split, labels, traces and arithmetic.
- [Source audit](rigorous/SOURCE_AUDIT.md): what was included and why the network dataset was excluded.
- [Notebook](rigorous/analysis.ipynb): recompute scores from the saved responses. Start Jupyter in `rigorous/`.

After setup, regenerate the primary results with `python rigorous/analyze.py`. To add the recorded follow-up results and rebuild the notebook, run `(cd rigorous && ../.venv/bin/python finish.py)`.

`artifacts/` holds compressed traces and inputs with a checksum manifest. `dfir/` contains the earlier DFIR Report scenarios. See [data attribution](DATA_LICENSES.md) for source licenses.
