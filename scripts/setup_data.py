#!/usr/bin/env python3
"""Restore checked-in evidence and fetch pinned public JSON. Standard library only."""
import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HOSTS = {'raw.githubusercontent.com', 'media.githubusercontent.com'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(root, relative):
    if Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('Manifest paths must be relative and remain inside the repository')
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Manifest path escapes the repository')
    return path


def verify(data, entry):
    if len(data) != entry['bytes'] or sha(data) != entry['sha256']:
        raise ValueError('Size or SHA-256 mismatch: ' + entry['path'])


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
            temporary = Path(f.name)
            f.write(data)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def restore(root=ROOT):
    entries = json.loads((root / 'artifacts/manifest.json').read_text())['files']
    for entry in entries:
        dest = safe_path(root, entry['path'])
        if dest.exists():
            verify(dest.read_bytes(), entry)
            continue
        archive = safe_path(root, entry['archive'])
        if sha(archive.read_bytes()) != entry['archive_sha256']:
            raise ValueError('Archive checksum mismatch: ' + entry['archive'])
        with gzip.open(archive, 'rb') as f:
            data = f.read(entry['bytes'] + 1)
        verify(data, entry)
        atomic_write(dest, data)
    return len(entries)


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Source URL must be a pinned public GitHub content URL')


class PinnedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(entry, root=ROOT):
    dest = safe_path(root, entry['path'])
    if dest.exists():
        verify(dest.read_bytes(), entry)
        return 'verified'
    validate_url(entry['url'])
    request = urllib.request.Request(entry['url'], headers={'User-Agent': 'jev-soc-bench-source-loader'})
    with urllib.request.build_opener(PinnedRedirects()).open(request, timeout=60) as response:
        validate_url(response.url)
        data = response.read(entry['bytes'] + 1)
    verify(data, entry)
    atomic_write(dest, data)
    return 'downloaded'


def setup(offline=False, include_network=False):
    restored = restore()
    print(f'Verified/restored {restored} recorded evidence files.', flush=True)
    if offline:
        print('Offline mode: public source downloads skipped.')
        return
    entries = json.loads((ROOT / 'data-sources.json').read_text())['files']
    entries = [e for e in entries if not e.get('optional') or include_network]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(fetch, entries))
    print(f'Public sources: {outcomes.count("downloaded")} downloaded, {outcomes.count("verified")} already verified. No API calls.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='Restore recorded evidence only; no network')
    parser.add_argument('--include-network', action='store_true', help='Also fetch the excluded SOCBench parquet for auditing')
    args = parser.parse_args()
    setup(args.offline, args.include_network)
