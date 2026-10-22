from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from sentryscope.config import Policy,Suppression
from sentryscope.scanner import discover,scan,analyze_source


class Scanner(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.root=Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self,name,text):
        path=self.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text,encoding='utf-8')
        return path

    def test_never_imports_or_executes_source(self):
        marker=self.root/'side-effect.txt'
        self.write('danger.py',f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\neval(input())')
        result=scan(self.root)
        self.assertTrue(result.complete)
        self.assertFalse(marker.exists())
        self.assertIn('PY001',{finding.rule_id for finding in result.findings})

    def test_determinism_across_worker_counts(self):
        for index in range(20): self.write(f'file{index:02}.py','eval(input())')
        serial=scan(self.root,replace(Policy(),workers=1))
        concurrent=scan(self.root,replace(Policy(),workers=8))
        self.assertEqual([f.to_dict() for f in serial.findings],[f.to_dict() for f in concurrent.findings])

    def test_default_exclusions(self):
        self.write('.venv/hidden.py','eval(input())')
        self.write('ok.py','value=1')
        result=scan(self.root)
        self.assertEqual(result.files_scanned,1)
        self.assertEqual(result.findings,[])

    def test_symlinks_do_not_escape_root(self):
        with tempfile.TemporaryDirectory() as outside:
            target=Path(outside)/'outside.py'
            target.write_text('eval(input())')
            try: (self.root/'linked.py').symlink_to(target)
            except OSError: self.skipTest('Symbolic links unavailable for this account')
            result=scan(self.root)
            self.assertEqual(result.findings,[])
            self.assertEqual(result.files_skipped,1)

    def test_large_file_marks_scan_incomplete(self):
        self.write('large.py','x=1\n'*10)
        result=scan(self.root,replace(Policy(),max_file_bytes=10))
        self.assertFalse(result.complete)
        self.assertEqual(result.diagnostics[0].category,'budget')

    def test_file_count_and_total_byte_budgets(self):
        self.write('a.py','x=1')
        self.write('b.py','x=2')
        for policy in (replace(Policy(),max_files=1),replace(Policy(),max_total_bytes=4)):
            with self.subTest(policy=policy): self.assertFalse(scan(self.root,policy).complete)

    def test_syntax_error_marks_scan_incomplete(self):
        self.write('broken.py','def :')
        result=scan(self.root)
        self.assertFalse(result.complete)
        self.assertEqual(result.files_scanned,1)

    def test_empty_file_is_counted(self):
        self.write('empty.py','')
        self.assertEqual(scan(self.root).files_scanned,1)

    def test_python_encoding_cookie(self):
        path=self.root/'legacy.py'
        path.write_bytes('# coding: latin-1\nname="caf\xe9"\n'.encode('latin-1'))
        self.assertTrue(scan(self.root).complete)

    def test_invalid_encoding_is_not_silently_ignored(self):
        (self.root/'invalid.py').write_bytes(b'\xff\xfe\x00')
        self.assertFalse(scan(self.root).complete)

    def test_modified_source_is_rejected(self):
        path=self.write('app.py','x=1')
        policy=Policy()
        sources,_,_=discover(self.root,policy)
        path.write_text('changed=True')
        _,errors,size=analyze_source(sources[0],self.root,policy)
        self.assertIsNone(size)
        self.assertEqual(errors[0].category,'read')

    def test_disabled_rule(self):
        self.write('app.py','eval(input())')
        result=scan(self.root,replace(Policy(),disabled_rules=('PY001',)))
        self.assertEqual(result.findings,[])

    def test_suppression_preserves_report_but_exempts_gate(self):
        self.write('app.py','eval(input())')
        first=scan(self.root)
        policy=replace(Policy(),suppressions=(Suppression(first.findings[0].fingerprint,'Reviewed isolated case','2099-01-01'),))
        result=scan(self.root,policy)
        self.assertEqual(len(result.findings),1)
        self.assertTrue(result.findings[0].suppressed)
        self.assertFalse(result.fails('high'))

    def test_invalid_root(self):
        with self.assertRaises(ValueError): scan(self.root/'missing')

    def test_manifests_are_scanned(self):
        self.write('requirements.txt','package>=1')
        self.write('Dockerfile','FROM python:3.12')
        self.assertEqual({finding.rule_id for finding in scan(self.root).findings},{'DEP001','CFG001','CFG002'})
