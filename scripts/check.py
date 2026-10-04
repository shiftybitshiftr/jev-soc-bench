#!/usr/bin/env python3
"""Run local tests and independently verify the recorded evaluation. No API calls."""
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.setup_data import ROOT, restore


def main():
    restore()
    sources = ROOT / 'rigorous/vendor/CrowdStrike_CyberSOCEval_data/data/hybrid-analysis/infostealers'
    if not sources.exists():
        raise SystemExit('First run: python scripts/setup_data.py (downloads pinned public source data).')
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-v'], cwd=ROOT, check=True)
    subprocess.run([sys.executable, '-m', 'unittest', 'test_rigorous', '-v'], cwd=ROOT/'rigorous', check=True)
    subprocess.run([sys.executable, 'validate_results.py'], cwd=ROOT/'rigorous', check=True)


if __name__ == '__main__':
    main()
