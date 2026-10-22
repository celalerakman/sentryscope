from dataclasses import replace
from datetime import date
from pathlib import Path
import tempfile
import unittest

from sentryscope.baseline import export_baseline,load_baseline
from sentryscope.config import Policy,load_policy
import json


class PolicyParsing(unittest.TestCase):
    def load(self,text):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'policy.toml'
            path.write_text(text)
            return load_policy(path,today=date(2026,1,1))

    def test_defaults(self):
        self.assertEqual(load_policy(),Policy())

    def test_explicit_policy(self):
        policy=self.load('[scan]\nworkers=2\nfail_on="medium"\ndisabled_rules=["PY007"]\nexclude=["build/**"]')
        self.assertEqual(policy.workers,2)
        self.assertEqual(policy.disabled_rules,('PY007',))

    def test_unknown_sections_and_keys(self):
        for text in ('[other]\na=1','[scan]\nworkres=2'):
            with self.subTest(text=text),self.assertRaises(ValueError): self.load(text)

    def test_numeric_bounds_and_boolean_rejection(self):
        for text in ('workers=0','workers=33','workers=true','max_files=-1','max_file_bytes=999999999'):
            with self.subTest(text=text),self.assertRaises(ValueError): self.load('[scan]\n'+text)

    def test_unknown_rules_and_severity(self):
        for text in ('disabled_rules=["UNKNOWN"]','fail_on="urgent"'):
            with self.subTest(text=text),self.assertRaises(ValueError): self.load('[scan]\n'+text)

    def test_invalid_exclusions(self):
        for value in ('[""]','[1]','"build"'):
            with self.subTest(value=value),self.assertRaises(ValueError): self.load('[scan]\nexclude='+value)

    def test_valid_expiring_suppression(self):
        text='[[suppressions]]\nfingerprint="'+'a'*64+'"\nreason="Reviewed isolated fixture"\nexpires=2026-12-31'
        self.assertEqual(self.load(text).suppressions[0].expires,'2026-12-31')

    def test_expired_or_unreasoned_suppression_is_rejected(self):
        for reason,expiry in [('Reviewed fixture','2025-12-31'),('ok','2027-01-01')]:
            text=f'[[suppressions]]\nfingerprint="'+ 'a'*64+f'"\nreason="{reason}"\nexpires={expiry}'
            with self.subTest(reason=reason),self.assertRaises(ValueError): self.load(text)

    def test_duplicate_suppression_is_rejected(self):
        text='[[suppressions]]\nfingerprint="'+'a'*64+'"\nreason="Reviewed isolated fixture"\nexpires=2026-12-31\n'
        with self.assertRaises(ValueError): self.load(text+text)

    def test_policy_hash_is_deterministic_and_configuration_sensitive(self):
        self.assertEqual(Policy().fingerprint,Policy().fingerprint)
        self.assertNotEqual(Policy().fingerprint,replace(Policy(),workers=2).fingerprint)


class Baselines(unittest.TestCase):
    def load(self,data,project='app'):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'baseline.json'
            path.write_text(json.dumps(data))
            return load_baseline(path,project)

    def test_round_trip(self):
        self.assertEqual(self.load(export_baseline('app',[],'a'*64)),frozenset())

    def test_project_mismatch(self):
        with self.assertRaises(ValueError): self.load(export_baseline('other',[],'a'*64))

    def test_invalid_fingerprint_and_duplicates(self):
        for values in (['not-a-hash'],['a'*64,'a'*64],[None]):
            with self.subTest(values=values),self.assertRaises(ValueError):
                self.load({**export_baseline('app',[],'a'*64),'fingerprints':values})

    def test_unsupported_schema(self):
        with self.assertRaises(ValueError): self.load({'schema_version':999,'project':'app','fingerprints':[]})

    def test_policy_and_engine_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'baseline.json'
            data=export_baseline('app',[],'a'*64)
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): load_baseline(path,'app','b'*64)
            data['engine_version']='999.0'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): load_baseline(path,'app')
