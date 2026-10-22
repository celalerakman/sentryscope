from pathlib import Path
import unittest
from sentryscope.scanner import scan

ROOT=Path(__file__).resolve().parents[1]


class Examples(unittest.TestCase):
    def test_unsafe_expected_rules(self):
        result=scan(ROOT/'examples'/'unsafe')
        self.assertTrue(result.complete)
        self.assertTrue({'PY001','PY002','PY003','PY004','PY007','PY008','PY010','PY011','PY014',
                         'DEP001','CFG001','CFG002'}<={finding.rule_id for finding in result.findings})

    def test_clean_example(self):
        result=scan(ROOT/'examples'/'clean')
        self.assertTrue(result.complete)
        self.assertEqual(result.findings,[])
