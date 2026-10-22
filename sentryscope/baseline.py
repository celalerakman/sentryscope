"""Portable finding baselines with bounded input and project identity checks."""
import json
from pathlib import Path
from . import __version__


def export_baseline(project,findings,policy_digest):
    return {'schema_version':1,'engine_version':__version__,'project':project,'policy_digest':policy_digest,
            'fingerprints':sorted({finding.fingerprint for finding in findings})}


def load_baseline(path,project,policy_digest=None):
    with Path(path).open('rb') as stream:
        raw = stream.read(10_485_761)
    if len(raw)>10_485_760:
        raise ValueError('Baseline size budget exceeded')
    data = json.loads(raw)
    if (not isinstance(data,dict) or data.get('schema_version')!=1 or
            data.get('project')!=project or not isinstance(data.get('fingerprints'),list)):
        raise ValueError('Baseline schema or project mismatch')
    if data.get('engine_version')!=__version__:
        raise ValueError('Baseline engine version mismatch')
    if policy_digest is not None and data.get('policy_digest')!=policy_digest:
        raise ValueError('Baseline policy mismatch')
    fingerprints = data['fingerprints']
    if len(fingerprints)>100_000 or any(not isinstance(value,str) or len(value)!=64 or
            any(char not in '0123456789abcdef' for char in value) for value in fingerprints):
        raise ValueError('Invalid baseline fingerprints')
    if len(set(fingerprints))!=len(fingerprints):
        raise ValueError('Duplicate baseline fingerprints')
    return frozenset(fingerprints)
