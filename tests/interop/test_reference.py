"""Frozen release fixtures must retain their recorded identity and provenance."""
import hashlib
import json
from pathlib import Path
import unittest
import zipfile


class FrozenReferenceTests(unittest.TestCase):
    def test_frozen_official_archives_match_manifest(self):
        root = Path(__file__).with_name('reference')
        manifest = json.loads((root / 'manifest.json').read_text())
        self.assertEqual(manifest['producer'], ['cryptofs-2.9.0.jar', 'cryptolib-2.2.1.jar'])
        self.assertEqual({case['scheme'] for case in manifest['cases']}, {'SIV_GCM', 'SIV_CTRMAC'})
        self.assertEqual(len(manifest['cases']), 2)
        for case in manifest['cases']:
            archive = root / case['archive']
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), case['sha256'])
            with zipfile.ZipFile(archive) as reader:
                self.assertIsNone(reader.testzip())
                self.assertIn('masterkey.cryptomator', reader.namelist())
                self.assertIn('vault.cryptomator', reader.namelist())
            report = json.loads((root / (archive.stem + '-oracle.json')).read_text())
            self.assertTrue(report['pass'])
            self.assertEqual(report['scheme'], case['scheme'])
            self.assertEqual(len(report['checked']), 7)
