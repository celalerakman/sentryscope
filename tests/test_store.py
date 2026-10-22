from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from sentryscope.models import Diagnostic,ScanResult
from sentryscope.python import analyze_python
from sentryscope.store import Store


def result(source='eval(input())'):
    findings,errors=analyze_python(source,'app.py')
    return ScanResult(findings=findings,diagnostics=errors,files_scanned=1,policy_digest='a'*64)


class Persistence(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.path=Path(self.directory.name)/'findings.sqlite'
        self.store=Store(self.path)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_save_round_trip(self):
        source=result()
        scan_id=self.store.save('app',source)
        snapshot=self.store.get(scan_id)
        self.assertEqual(snapshot['findings'],source.findings)
        self.assertEqual(snapshot['project'],'app')
        self.assertTrue(self.store.verify_audit())

    def test_triage_version_and_reason(self):
        scan_id=self.store.save('app',result())
        fingerprint=self.store.get(scan_id)['findings'][0].fingerprint
        self.assertEqual(self.store.transition('app',fingerprint,'reviewing',0,'local','Inspecting this operation'),
                         {'status':'reviewing','version':1})
        with self.assertRaises(ValueError):
            self.store.transition('app',fingerprint,'accepted',0,'local','An outdated decision')
        self.assertEqual(self.store.findings(scan_id)[0]['version'],1)
        self.assertEqual(len(self.store.audit()),2)
        self.assertTrue(self.store.verify_audit())

    def test_invalid_state_reason_and_actor(self):
        scan_id=self.store.save('app',result())
        fingerprint=self.store.get(scan_id)['findings'][0].fingerprint
        for status,actor,reason in [('open','local','Already open'),('invalid','local','Reviewed case'),
                                    ('reviewing','','Reviewed case'),('reviewing','local','ok')]:
            with self.subTest(status=status,actor=actor),self.assertRaises(ValueError):
                self.store.transition('app',fingerprint,status,0,actor,reason)
        self.assertEqual(len(self.store.audit()),1)

    def test_reappearing_finding_keeps_triage(self):
        first=self.store.save('app',result())
        fingerprint=self.store.get(first)['findings'][0].fingerprint
        self.store.transition('app',fingerprint,'accepted',0,'local','Reviewed isolated use')
        second=self.store.save('app',result('# moved\n\neval(input())'))
        self.assertEqual(self.store.findings(second)[0]['status'],'accepted')
        self.assertTrue(self.store.verify_audit())

    def test_project_isolation(self):
        first=self.store.save('one',result())
        second=self.store.save('two',result())
        fingerprint=self.store.get(first)['findings'][0].fingerprint
        self.store.transition('one',fingerprint,'resolved',0,'local','Operation was removed')
        self.assertEqual(self.store.findings(second)[0]['status'],'open')
        with self.assertRaises(ValueError): self.store.compare(first,second)

    def test_diff_tracks_new_absent_and_unchanged(self):
        first=self.store.save('app',result('eval(input())\nimport tempfile\ntempfile.mktemp()'))
        second=self.store.save('app',result('eval(input())\nimport hashlib\nhashlib.md5(b"x")'))
        diff=self.store.compare(first,second)
        self.assertEqual((len(diff['new']),len(diff['absent']),len(diff['unchanged'])),(1,1,1))
        self.assertTrue(diff['complete'])

    def test_incomplete_diff_never_claims_complete_resolution(self):
        first=self.store.save('app',result())
        incomplete=ScanResult(diagnostics=[Diagnostic('app.py','parse','Could not parse')])
        second=self.store.save('app',incomplete)
        self.assertFalse(self.store.compare(first,second)['complete'])

    def test_duplicate_occurrence_rolls_back_entire_scan(self):
        duplicate=result()
        duplicate.findings*=2
        with self.assertRaises(sqlite3.IntegrityError): self.store.save('app',duplicate)
        self.assertEqual(self.store.scans(),[])
        self.assertEqual(self.store.audit(),[])
        self.assertTrue(self.store.verify_audit())

    def test_audit_update_and_delete_are_denied(self):
        self.store.save('app',result())
        for statement in ('UPDATE audit SET previous_hash="x"','DELETE FROM audit'):
            with self.subTest(statement=statement),self.assertRaises(sqlite3.IntegrityError):
                self.store.db.execute(statement)

    def test_detects_event_tampering(self):
        self.store.save('app',result())
        self.store.db.execute('DROP TRIGGER audit_no_update')
        self.store.db.execute('UPDATE audit SET payload=?',('{"kind":"forged"}',))
        self.assertFalse(self.store.verify_audit())

    def test_detects_tail_deletion(self):
        self.store.save('app',result())
        self.store.db.execute('DROP TRIGGER audit_no_delete')
        self.store.db.execute('DELETE FROM audit')
        self.assertFalse(self.store.verify_audit())

    def test_detects_snapshot_tampering(self):
        self.store.save('app',result())
        self.store.db.execute('UPDATE occurrences SET payload=?',('{}',))
        self.assertFalse(self.store.verify_audit())

    def test_detects_triage_tampering(self):
        self.store.save('app',result())
        self.store.db.execute('UPDATE triage SET status="accepted"')
        self.assertFalse(self.store.verify_audit())

    def test_backup_and_restore_verifies_chain(self):
        scan_id=self.store.save('app',result())
        destination=Path(self.directory.name)/'backup.sqlite'
        self.store.backup(destination)
        with Store(destination) as restored:
            self.assertEqual(restored.get(scan_id),self.store.get(scan_id))
            self.assertTrue(restored.verify_audit())

    def test_concurrent_triage_has_one_winner(self):
        scan_id=self.store.save('app',result())
        fingerprint=self.store.get(scan_id)['findings'][0].fingerprint
        def change(actor):
            with Store(self.path) as store:
                try:
                    store.transition('app',fingerprint,'reviewing',0,actor,'Reviewing this operation')
                    return True
                except ValueError:
                    return False
        with ThreadPoolExecutor(max_workers=2) as executor:
            winners=list(executor.map(change,['first','second']))
        self.assertEqual(sum(winners),1)
        self.assertTrue(self.store.verify_audit())

    def test_schema_version_guard(self):
        self.store.db.execute('UPDATE metadata SET value="999" WHERE key="schema_version"')
        with self.assertRaises(ValueError): Store(self.path)

    def test_unknown_scan_and_finding(self):
        with self.assertRaises(ValueError): self.store.get('missing')
        with self.assertRaises(ValueError):
            self.store.transition('app','a'*64,'reviewing',0,'local','Reviewing operation')
