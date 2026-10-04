# Jev SOC test bench

Evaluate where **Jev fits in a security operations pipeline**: reading evidence, handling cloud identities, choosing investigation tools, recommending containment and enforcing response policy.

Start with **[FINDINGS.md](FINDINGS.md)** for the results, charts and takeaways from our 3,364-call evaluation. The bench runs locally; inference uses the hosted Jev API. It does not execute malware or contain real systems.

## Set up

Use Python **3.9–3.12**; the recorded dependency versions are pinned. Python 3.11 is used in CI.

```sh
git clone https://github.com/shiftybitshiftr/jev-soc-bench.git
cd jev-soc-bench
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/setup_data.py
python scripts/check.py
```

`setup_data.py` restores the compressed evaluation evidence and downloads about **33 MB** of pinned public source data. Every file is checked against its size and SHA-256. Setup and validation make **no Jev API calls** and need no API key.

For the saved findings alone, no setup is needed. To restore traces without downloading source data, use `python scripts/setup_data.py --offline`.

## Run a new evaluation

Inject your Jev key as **`TYPESAFE_API_KEY`** through your secret manager, then run:

```sh
python scripts/new_run.py --output runs/my-eval --execute
```

Each run gets a new directory; it cannot overwrite the recorded evaluation. Omit `--execute` to stage the run without contacting Jev. The output includes `rigorous/REPORT.md`, charts, `results/metrics.json` and exact request/response traces.

To include the compact-evidence and repeat-control experiments:

```sh
python scripts/new_run.py --output runs/my-full-eval --execute --followups
```

The model is pinned to **`jev-1.13.0`**. The complete suite is bounded at **3,500 API attempts / 35 million input tokens**. Our recorded run cost approximately **$1.05**; the ceiling is **$1.47 at the rate used in that run**, not a guarantee of current pricing. Follow-up scores remain separate from the primary report.

Never put a key in a command argument, tracked file or notebook. If you use Fishnet OpenBao, the existing scoped injection command is:

```sh
fishnet-secrets run \
  --env TYPESAFE_API_KEY=codex/projects/jev-soc/dev#TYPESAFE_API_KEY \
  -- .venv/bin/python scripts/new_run.py --output runs/my-eval --execute
```

## What's included

| Path | Contents |
|---|---|
| [FINDINGS.md](FINDINGS.md) | Simplified findings, charts, metrics and pipeline recommendations |
| [rigorous/REPORT.md](rigorous/REPORT.md) | Full evaluation methodology and results |
| [rigorous/analysis.ipynb](rigorous/analysis.ipynb) | Executed analysis notebook; start Jupyter in `rigorous/` |
| [rigorous/CASE_AUDIT.md](rigorous/CASE_AUDIT.md) | Concrete failure examples and label qualifications |
| [rigorous/VALIDATION.md](rigorous/VALIDATION.md) | Evaluation checks and limitations |
| `artifacts/` | Compressed, checksum-verified frozen inputs and raw traces |
| `rigorous/results/` | Committed metrics and item scores; large traces restore here |
| `dfir/` | Earlier DFIR Report scenario evaluation |

To recompute the recorded primary metrics after setup: `python rigorous/analyze.py`. To regenerate its exploratory supplement and notebook: `cd rigorous && ../.venv/bin/python finish.py`.

New runs are ignored by Git. Source downloads and expanded large traces are also ignored; their pinned manifests and compressed snapshots are tracked. The original evaluation scripts remain intact where required by their recorded hashes. See [data attribution](DATA_LICENSES.md) before redistributing source-derived evidence.

The results support a bounded, supervised pilot. Public benchmark scores and authored policy fixtures do not establish production detection accuracy or safe autonomous containment.
