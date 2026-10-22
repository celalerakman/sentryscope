import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT=Path(__file__).resolve().parents[1]


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.root=Path(self.directory.name)
        self.source=self.root/'source'
        self.source.mkdir()
        self.db=self.root/'history.sqlite'

    def tearDown(self):
        self.directory.cleanup()

    def run_cli(self,*args,code=0):
        process=subprocess.run([sys.executable,'-m','sentryscope',*map(str,args)],cwd=ROOT,text=True,capture_output=True)
        self.assertEqual(process.returncode,code,process.stdout+process.stderr)
        return process.stdout

    def scan(self,code=0,*extra):
        return self.run_cli('scan',self.source,'--project','app','--database',self.db,'--format','json',*extra,code=code)

    def test_clean_scan_and_history(self):
        (self.source/'safe.py').write_text('value=1')
        snapshot=json.loads(self.scan())
        self.assertTrue(snapshot['complete'])
        history=json.loads(self.run_cli('history','--project','app','--database',self.db))
        self.assertEqual(history[0]['id'],snapshot['scan_id'])

    def test_finding_gate_and_baseline(self):
        (self.source/'app.py').write_text('eval(input())')
        first=json.loads(self.scan(1))
        baseline=self.root/'baseline.json'
        self.run_cli('baseline',first['scan_id'],'--output',baseline,'--database',self.db)
        second=json.loads(self.scan(0,'--baseline',baseline))
        self.assertEqual(second['findings'][0]['baseline_state'],'unchanged')

    def test_invalid_source_is_exit_two(self):
        (self.source/'bad.py').write_text('def :')
        self.assertFalse(json.loads(self.scan(2))['complete'])

    def test_incomplete_scan_cannot_be_baselined(self):
        (self.source/'bad.py').write_text('def :')
        snapshot=json.loads(self.scan(2))
        self.run_cli('baseline',snapshot['scan_id'],'--output',self.root/'bad.json','--database',self.db,code=2)

    def test_full_triage_report_diff_and_backup(self):
        (self.source/'app.py').write_text('eval(input())')
        first=json.loads(self.scan(1))
        fingerprint=first['findings'][0]['fingerprint']
        decision=json.loads(self.run_cli('triage',fingerprint,'--project','app','--status','reviewing',
            '--version','0','--actor','local','--reason','Inspecting the operation','--database',self.db))
        self.assertEqual(decision['version'],1)
        shown=json.loads(self.run_cli('show',first['scan_id'],'--database',self.db,'--status','reviewing'))
        self.assertEqual(shown[0]['status'],'reviewing')
        report=self.root/'report.html'
        self.run_cli('report',first['scan_id'],'--database',self.db,'--output',report)
        self.assertIn('Dynamic code execution',report.read_text())
        (self.source/'app.py').write_text('value=1')
        second=json.loads(self.scan())
        difference=json.loads(self.run_cli('diff',first['scan_id'],second['scan_id'],'--database',self.db))
        self.assertEqual(difference['absent'],[fingerprint])
        self.assertTrue(json.loads(self.run_cli('audit','--verify','--database',self.db))['valid'])
        backup=self.root/'backup.sqlite'
        self.run_cli('backup',backup,'--database',self.db)
        self.assertTrue(json.loads(self.run_cli('audit','--verify','--database',backup))['valid'])

    def test_no_store_and_report_output(self):
        output=self.root/'report.sarif'
        self.run_cli('scan',self.source,'--no-store','--format','sarif','--output',output,'--database',self.db)
        self.assertEqual(json.loads(output.read_text())['version'],'2.1.0')
        self.assertFalse(self.db.exists())

    def test_rules_and_version(self):
        self.assertTrue(any(rule['id']=='PY003' for rule in json.loads(self.run_cli('rules'))))
        self.assertEqual(self.run_cli('--version').strip(),'0.1.0')

    def test_invalid_root_is_exit_two(self):
        self.run_cli('scan',self.root/'missing','--no-store',code=2)


if __name__=='__main__':
    unittest.main()
