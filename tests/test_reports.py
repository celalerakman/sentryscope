from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from sentryscope.models import Diagnostic,ScanResult
from sentryscope.python import analyze_python
from sentryscope.reports import atomic_output,document,html_report,render,sarif


def result(path='app.py'):
    findings,_=analyze_python('value=input()\ncursor.execute(value)',path)
    return ScanResult(findings=findings,files_scanned=1)


class Reports(unittest.TestCase):
    def test_json_round_trip(self):
        report=json.loads(render(result(),'json',scan_id='scan',project='app'))
        self.assertEqual(report['scan_id'],'scan')
        self.assertEqual(report['findings'][0]['rule_id'],'PY003')

    def test_sarif_shape_and_trace(self):
        report=sarif(result())
        self.assertEqual(report['version'],'2.1.0')
        run=report['runs'][0]
        finding=run['results'][0]
        self.assertEqual(run['tool']['driver']['rules'][finding['ruleIndex']]['id'],finding['ruleId'])
        self.assertIn('codeFlows',finding)
        self.assertTrue(run['invocations'][0]['executionSuccessful'])

    def test_sarif_escapes_uri_and_keeps_relative_path(self):
        report=sarif(result('src/a b%name.py'))
        uri=report['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertEqual(uri,'src/a%20b%25name.py')

    def test_sarif_baseline_and_suppression(self):
        source=result()
        finding=source.findings[0]
        source.findings[0]=replace(finding,suppressed=True,suppression_reason='Reviewed local operation')
        entry=sarif(source,{finding.fingerprint})['runs'][0]['results'][0]
        self.assertEqual(entry['baselineState'],'unchanged')
        self.assertEqual(entry['suppressions'][0]['kind'],'external')

    def test_incomplete_invocation(self):
        source=result()
        source.diagnostics=[Diagnostic('bad.py','parse','Could not parse')]
        self.assertFalse(sarif(source)['runs'][0]['invocations'][0]['executionSuccessful'])
        self.assertIn('Incomplete scan',html_report(source))

    def test_html_injection_is_escaped(self):
        report=html_report(result('src/<img src=x onerror=alert(1)>.py'),project='<script>alert(1)</script>')
        self.assertNotIn('<img src=x',report)
        self.assertNotIn('<script>alert(1)',report)
        self.assertIn('&lt;script&gt;',report)
        self.assertIn('aria-live="polite"',report)

    def test_literal_secret_is_absent_from_every_report(self):
        secret='u7Yk3R9q5L2m8V4z'
        findings,_=analyze_python(f'password="{secret}"','app.py')
        source=ScanResult(findings=findings)
        for format in ('json','text','html','sarif'):
            with self.subTest(format=format): self.assertNotIn(secret,render(source,format))

    def test_atomic_report_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'nested'/'report.json'
            atomic_output(path,'old')
            atomic_output(path,'new')
            self.assertEqual(path.read_text(),'new')
            self.assertEqual(len(list(path.parent.iterdir())),1)

    def test_unknown_format(self):
        with self.assertRaises(ValueError): render(result(),'unknown')
