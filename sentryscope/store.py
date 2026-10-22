"""Transactional scan snapshots, triage versions and hash-chained audit events."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from .models import Finding, ScanResult, canonical, digest

SCHEMA = '''
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO metadata VALUES ('schema_version','1');
CREATE TABLE IF NOT EXISTS scans(
 id TEXT PRIMARY KEY,project TEXT NOT NULL,created_at TEXT NOT NULL,
 policy_digest TEXT NOT NULL,complete INTEGER NOT NULL,summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_project ON scans(project,created_at);
CREATE TABLE IF NOT EXISTS occurrences(
 scan_id TEXT NOT NULL REFERENCES scans(id),fingerprint TEXT NOT NULL,
 payload TEXT NOT NULL,PRIMARY KEY(scan_id,fingerprint)
);
CREATE INDEX IF NOT EXISTS occurrence_fingerprint ON occurrences(fingerprint);
CREATE TABLE IF NOT EXISTS triage(
 project TEXT NOT NULL,fingerprint TEXT NOT NULL,status TEXT NOT NULL
 CHECK(status IN ('open','reviewing','accepted','resolved')),
 version INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(project,fingerprint)
);
CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL,
 previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT,'Audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT,'Audit is append-only'); END;
'''

TRANSITIONS = {
    'open': {'reviewing','accepted','resolved'},
    'reviewing': {'open','accepted','resolved'},
    'accepted': {'open','reviewing'},
    'resolved': {'open','reviewing'},
}


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


class Store:
    def __init__(self,path):
        path = Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        self.db = sqlite3.connect(path,timeout=10,isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript(SCHEMA)
        if self.db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0]!='1':
            self.close()
            raise ValueError('Unsupported database schema version')

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def _event(self,kind,data):
        row = self.db.execute('SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        previous = row[0] if row else '0'*64
        payload = canonical({'kind':kind,'at':timestamp(),**data})
        event_hash = digest([previous,payload])
        self.db.execute('INSERT INTO audit(payload,previous_hash,event_hash) VALUES (?,?,?)',
                        (payload,previous,event_hash))

    def save(self,project,result):
        if not isinstance(project,str) or not project.strip() or len(project)>200:
            raise ValueError('A short, non-empty project identifier is required')
        scan_id = uuid.uuid4().hex
        summary = result.to_dict()
        summary.pop('findings')
        with self.transaction():
            self.db.execute('INSERT INTO scans VALUES (?,?,?,?,?,?)',
                            (scan_id,project,timestamp(),result.policy_digest,int(result.complete),canonical(summary)))
            for finding in result.findings:
                self.db.execute('INSERT INTO occurrences VALUES (?,?,?)',
                                (scan_id,finding.fingerprint,canonical(finding.to_dict())))
                self.db.execute('INSERT OR IGNORE INTO triage(project,fingerprint,status) VALUES (?,?,?)',
                                (project,finding.fingerprint,'open'))
            self._event('scan.saved',{'project':project,'scan_id':scan_id,
                        'findings':len(result.findings),'snapshot_hash':self._snapshot_hash(scan_id)})
        return scan_id

    def scans(self,project=None):
        if project is None:
            rows = self.db.execute('SELECT id,project,created_at,complete FROM scans ORDER BY created_at,id')
        else:
            rows = self.db.execute('SELECT id,project,created_at,complete FROM scans WHERE project=? ORDER BY created_at,id',(project,))
        return [dict(row) for row in rows]

    def get(self,scan_id):
        row = self.db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown scan')
        findings = [Finding.from_dict(json.loads(item[0])) for item in self.db.execute(
            'SELECT payload FROM occurrences WHERE scan_id=? ORDER BY fingerprint',(scan_id,))]
        summary = json.loads(row['summary'])
        return {'id':scan_id,'project':row['project'],'created_at':row['created_at'],
                'findings':findings,'summary':summary}

    def findings(self,scan_id,status=None):
        scan = self.get(scan_id)
        states = {row['fingerprint']:dict(row) for row in self.db.execute(
            'SELECT fingerprint,status,version FROM triage WHERE project=?',(scan['project'],))}
        return [{**finding.to_dict(),**states[finding.fingerprint]} for finding in scan['findings']
                if status is None or states[finding.fingerprint]['status']==status]

    def transition(self,project,fingerprint,status,version,actor,reason):
        if status not in TRANSITIONS or type(version) is not int or version<0:
            raise ValueError('Invalid triage state/version')
        if not isinstance(actor,str) or not actor.strip() or len(actor)>100:
            raise ValueError('An actor identifier is required')
        if not isinstance(reason,str) or len(reason.strip())<8 or len(reason)>2000:
            raise ValueError('A meaningful triage reason is required')
        with self.transaction():
            row = self.db.execute('SELECT * FROM triage WHERE project=? AND fingerprint=?',
                                  (project,fingerprint)).fetchone()
            if row is None:
                raise ValueError('Unknown finding in project')
            if row['version']!=version:
                raise ValueError('Stale triage version')
            if status not in TRANSITIONS[row['status']]:
                raise ValueError('Invalid triage transition')
            self.db.execute('UPDATE triage SET status=?,version=version+1 WHERE project=? AND fingerprint=? AND version=?',
                            (status,project,fingerprint,version))
            self._event('finding.triaged',{'project':project,'fingerprint':fingerprint,
                        'from':row['status'],'to':status,'version':version+1,
                        'actor':actor.strip(),'reason':reason.strip()})
        return {'status':status,'version':version+1}

    def compare(self,before,after):
        left,right = self.get(before),self.get(after)
        if left['project']!=right['project']:
            raise ValueError('Cannot compare scans from different projects')
        if not left['summary'].get('diagnostics') and not right['summary'].get('diagnostics'):
            complete = True
        else:
            complete = False
        old = {finding.fingerprint:finding for finding in left['findings']}
        new = {finding.fingerprint:finding for finding in right['findings']}
        return {'before':before,'after':after,'complete':complete,
                'new':sorted(new.keys()-old.keys()),'unchanged':sorted(new.keys()&old.keys()),
                'absent':sorted(old.keys()-new.keys())}

    def _snapshot_hash(self,scan_id):
        row = self.db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        if row is None:
            return None
        findings = [json.loads(item[0]) for item in self.db.execute(
            'SELECT payload FROM occurrences WHERE scan_id=? ORDER BY fingerprint',(scan_id,))]
        return digest({'id':scan_id,'project':row['project'],'created_at':row['created_at'],
                       'policy_digest':row['policy_digest'],'complete':row['complete'],
                       'summary':json.loads(row['summary']),'findings':findings})

    def verify_audit(self):
        try:
            return self._verify_audit()
        except (ValueError,KeyError,TypeError):
            return False

    def _verify_audit(self):
        previous,expected_seq = '0'*64,1
        expected_states,scan_ids = {},set()
        for row in self.db.execute('SELECT * FROM audit ORDER BY seq'):
            if row['seq']!=expected_seq or row['previous_hash']!=previous:
                return False
            if digest([previous,row['payload']])!=row['event_hash']:
                return False
            event = json.loads(row['payload'])
            if event['kind']=='scan.saved':
                scan_id = event['scan_id']
                if self._snapshot_hash(scan_id)!=event['snapshot_hash'] or scan_id in scan_ids:
                    return False
                scan_ids.add(scan_id)
                for finding in self.db.execute('SELECT fingerprint FROM occurrences WHERE scan_id=?',(scan_id,)):
                    expected_states.setdefault((event['project'],finding[0]),('open',0))
            elif event['kind']=='finding.triaged':
                key = (event['project'],event['fingerprint'])
                current = expected_states.get(key)
                if current is None or current[0]!=event['from'] or current[1]+1!=event['version']:
                    return False
                expected_states[key] = (event['to'],event['version'])
            else:
                return False
            previous,expected_seq = row['event_hash'],expected_seq+1
        # Detect deletion of a tail event by comparing its terminal sequence with
        # SQLite's autoincrement high-water mark. A database owner can forge both.
        high_water = self.db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit'").fetchone()
        if (high_water[0] if high_water else 0)!=expected_seq-1:
            return False
        actual_states = {(row['project'],row['fingerprint']):(row['status'],row['version'])
                         for row in self.db.execute('SELECT * FROM triage')}
        actual_scans = {row[0] for row in self.db.execute('SELECT id FROM scans')}
        return actual_states==expected_states and actual_scans==scan_ids

    def audit(self):
        return [dict(row) for row in self.db.execute('SELECT * FROM audit ORDER BY seq')]

    def backup(self,destination):
        target = sqlite3.connect(destination)
        try:
            self.db.backup(target)
        finally:
            target.close()
