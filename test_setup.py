import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts import setup_data
from scripts import new_run


class EvidenceSetup(unittest.TestCase):
    def fixture(self, root):
        data=b'{"example":true}\n';archive=gzip.compress(data,mtime=0)
        (root/'artifacts').mkdir();(root/'artifacts/example.gz').write_bytes(archive)
        entry={'path':'evidence/example.json','archive':'artifacts/example.gz','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'archive_sha256':hashlib.sha256(archive).hexdigest()}
        (root/'artifacts/manifest.json').write_text(json.dumps({'files':[entry]}))
        return data,entry
    def test_restore_verifies_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data,_=self.fixture(root)
            setup_data.restore(root);setup_data.restore(root)
            self.assertEqual((root/'evidence/example.json').read_bytes(),data)
    def test_corrupt_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);setup_data.restore(root)
            path=root/'evidence/example.json';path.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):setup_data.restore(root)
            self.assertEqual(path.read_bytes(),b'corrupt')
    def test_corrupt_archive_never_materializes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);(root/'artifacts/example.gz').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):setup_data.restore(root)
            self.assertFalse((root/'evidence/example.json').exists())
    def test_path_traversal_and_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaises(ValueError):setup_data.safe_path(root,'../outside')
            (root/'escape').symlink_to(root.parent,target_is_directory=True)
            with self.assertRaises(ValueError):setup_data.safe_path(root,'escape/outside')
    def test_downloader_never_persists_unverified_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data,entry=self.fixture(root)
            entry['url']='https://raw.githubusercontent.com/example/repo/commit/data.json'
            with patch('scripts.setup_data.urllib.request.build_opener') as opener:
                response=opener.return_value.open.return_value.__enter__.return_value
                response.url=entry['url'];response.read.return_value=b'wrong'
                with self.assertRaises(ValueError):setup_data.fetch(entry,root)
            self.assertFalse((root/entry['path']).exists())
    def test_unexpected_or_credentialed_url_rejected(self):
        for url in ('http://raw.githubusercontent.com/x','https://example.org/x','https://user:secret@raw.githubusercontent.com/x','https://raw.githubusercontent.com/x?token=secret'):
            with self.assertRaises(ValueError):setup_data.validate_url(url)
    def test_staged_run_contains_no_historical_results_or_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'isolated'
            with patch('scripts.new_run.restore'):
                new_run.stage(target)
            self.assertFalse((target/'rigorous/results').exists())
            self.assertFalse((target/'rigorous/evidence/dev-thresholds.json').exists())
            for name in new_run.INPUTS:
                self.assertEqual((target/'rigorous/evidence'/name).read_bytes(),(setup_data.ROOT/'rigorous/evidence'/name).read_bytes())
            with self.assertRaises(ValueError):new_run.stage(target)


if __name__=='__main__':unittest.main()
