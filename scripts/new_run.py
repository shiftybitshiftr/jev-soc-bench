#!/usr/bin/env python3
"""Stage an isolated evaluation; --execute explicitly enables hosted Jev calls."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.setup_data import ROOT, restore

RUNTIME = ('prepare.py', 'run.py', 'analyze.py', 'followup.py', 'repeat_control.py')
INPUTS = ('malware-cases.json', 'cloud-cases.json', 'policy-cases.json', 'frozen-plan.json', 'input-hashes.json', 'runtime-code-hashes.json')


def stage(output):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Output directory already exists. Choose a new name; recorded runs are never overwritten.')
    restore()
    evidence = output/'rigorous/evidence'
    evidence.mkdir(parents=True)
    for name in ('bench.py', 'fixtures.py'):
        shutil.copy2(ROOT/name, output/name)
    for name in RUNTIME:
        shutil.copy2(ROOT/'rigorous'/name, output/'rigorous'/name)
    for name in INPUTS:
        shutil.copy2(ROOT/'rigorous/evidence'/name, evidence/name)
    (output/'RUN_INFO.json').write_text(json.dumps({'model': 'jev-1.13.0', 'max_primary_attempts': 3500, 'max_primary_input_tokens': 35000000, 'source_plan': json.loads((evidence/'input-hashes.json').read_text())['frozen-plan'], 'historical_outputs_copied': False}, indent=2)+'\n')
    return output


def execute(output, followups=False):
    output = Path(output).resolve()
    if not os.environ.get('TYPESAFE_API_KEY'):
        raise SystemExit('TYPESAFE_API_KEY must be injected into the process environment; never pass a key on the command line.')
    if followups:
        source = ROOT/'rigorous/vendor/CrowdStrike_CyberSOCEval_data/data/hybrid-analysis'
        if not (source/'infostealers').exists():
            raise SystemExit('Follow-ups require public reports: run python scripts/setup_data.py first.')
        target = output/'rigorous/vendor/CrowdStrike_CyberSOCEval_data/data/hybrid-analysis'
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)
    subprocess.run([sys.executable, 'run.py'], cwd=output/'rigorous', check=True)
    subprocess.run([sys.executable, 'analyze.py'], cwd=output/'rigorous', check=True)
    if followups:
        for name in ('followup.py', 'repeat_control.py'):
            subprocess.run([sys.executable, name], cwd=output/'rigorous', check=True)
    print('Results:', output/'rigorous/results/metrics.json')
    print('Primary report:', output/'rigorous/REPORT.md')
    if followups:
        print('Follow-up traces and total-completion.json are also saved. The primary report does not combine exploratory scores.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='A new directory, e.g. runs/my-eval')
    parser.add_argument('--execute', action='store_true', help='Make billable hosted API calls after staging')
    parser.add_argument('--followups', action='store_true', help='Also run 609 compact-context calls and 60 repeat controls')
    args = parser.parse_args()
    if args.execute and not os.environ.get('TYPESAFE_API_KEY'):
        parser.error('TYPESAFE_API_KEY is not set. Inject it through your secret manager before --execute.')
    dest = stage(args.output)
    if args.execute:
        execute(dest, args.followups)
    else:
        print('Staged an isolated run at', dest, 'without any API calls.')
        print('To execute a staged run, use its rigorous/run.py with a securely injected TYPESAFE_API_KEY.')
