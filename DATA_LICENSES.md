# Data attribution and reuse

This repository contains authored test code, public-source data and derived evaluation artifacts. Upstream source licenses remain applicable to their respective material; no blanket license overrides them.

| Material | Upstream / pinned revision | Terms retained here |
|---|---|---|
| Sandbox JSON and derived report excerpts in frozen cases and request traces | [CrowdStrike CyberSOCEval_data](https://github.com/CrowdStrike/CyberSOCEval_data), `ce7daa5bc7da51559ca97476d2277be02631783e` | [Hybrid Analysis CC BY-SA 4.0 notice](rigorous/vendor/CrowdStrike_CyberSOCEval_data/data/hybrid-analysis/LICENSE.md); attribution to CrowdStrike/CyberSOCEval and Hybrid Analysis |
| Expert-reviewed questions and answer labels | [Meta PurpleLlama](https://github.com/meta-llama/PurpleLlama), `172c1074069eb88ec834124272c1b1c4f8893445` | [Benchmark-specific MIT notice](rigorous/vendor/meta-llama_PurpleLlama/CybersecurityBenchmarks/LICENSE) |
| Public lab cloud events and paired transformations | [Splunk attack_data](https://github.com/splunk/attack_data), `a92cc4e6d7e39d56a0840d206a0963eeee0e22db` | [Apache-2.0 notice](rigorous/vendor/splunk_attack_data/LICENSE) |
| Network corpus, optional download and excluded from scoring | [DeepTempo SOCBench](https://github.com/DeepTempo/socbench), `f27c91793b7e7f957cb63dadb3cf3ba78292fa3e` | [Upstream notice](rigorous/vendor/DeepTempo_socbench/LICENSE) |

Source URL, revision, content hash and size are recorded in `data-sources.json` and the source manifests. `artifacts/manifest.json` records the exact hashes of compressed and expanded evidence. Compression does not change the licenses of the underlying report excerpts or questions.

The earlier DFIR-derived fixtures paraphrase facts from six linked public incident reports. Their reconstructed telemetry, controls and expected decisions are authored for this bench; the original incident reports are not included. See [source references](dfir/evidence/sources.json).

This private evaluation repository does not include malware executables, account screenshots or API credentials. Public-source logs may contain upstream example identifiers, paths and indicators; those are evidence data, not instructions or live endpoints to contact.
