"""Strict TOML policy parsing, including reasoned and expiring suppressions."""
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
import tomllib

from .models import digest
from .rules import RULES

DEFAULT_EXCLUDES = ('.git', '.venv', 'venv', '__pycache__', 'node_modules', '.tox', 'runtime')


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: str


@dataclass(frozen=True)
class Policy:
    workers: int = 4
    max_file_bytes: int = 1_048_576
    max_files: int = 10_000
    max_total_bytes: int = 128 * 1_048_576
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    disabled_rules: tuple[str, ...] = ()
    fail_on: str = 'high'
    suppressions: tuple[Suppression, ...] = ()

    @property
    def fingerprint(self):
        return digest(asdict(self))


def _positive_integer(data, key, default, maximum):
    value = data.get(key, default)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f'{key} must be an integer between 1 and {maximum}')
    return value


def load_policy(path=None, today=None):
    if path is None:
        return Policy()
    today = today or date.today()
    with Path(path).open('rb') as stream:
        data = tomllib.load(stream)
    unknown = set(data) - {'scan', 'suppressions'}
    if unknown:
        raise ValueError('Unknown policy section: ' + ', '.join(sorted(unknown)))
    scan = data.get('scan', {})
    allowed = {'workers','max_file_bytes','max_files','max_total_bytes','exclude','disabled_rules','fail_on'}
    if not isinstance(scan, dict) or set(scan) - allowed:
        raise ValueError('Invalid scan policy keys')
    exclude = scan.get('exclude', list(DEFAULT_EXCLUDES))
    disabled = scan.get('disabled_rules', [])
    if not isinstance(exclude, list) or any(not isinstance(v,str) or not v for v in exclude):
        raise ValueError('exclude must contain non-empty patterns')
    if not isinstance(disabled, list) or any(v not in RULES for v in disabled):
        raise ValueError('disabled_rules contains an unknown rule')
    fail_on = scan.get('fail_on', 'high')
    if fail_on not in ('critical','high','medium','low'):
        raise ValueError('Unknown fail_on severity')
    suppressed = []
    raw_suppressions = data.get('suppressions', [])
    if not isinstance(raw_suppressions, list):
        raise ValueError('suppressions must be an array of tables')
    seen = set()
    for entry in raw_suppressions:
        if not isinstance(entry, dict) or set(entry) != {'fingerprint','reason','expires'}:
            raise ValueError('Suppression requires fingerprint, reason and expires')
        fingerprint = entry['fingerprint']
        if not isinstance(fingerprint, str) or len(fingerprint) != 64 or any(c not in '0123456789abcdef' for c in fingerprint):
            raise ValueError('Invalid suppression fingerprint')
        if fingerprint in seen:
            raise ValueError('Duplicate suppression')
        seen.add(fingerprint)
        if not isinstance(entry['reason'], str) or len(entry['reason'].strip()) < 8:
            raise ValueError('Suppression reason must explain the decision')
        expiry = date.fromisoformat(str(entry['expires']))
        if expiry < today:
            raise ValueError('Expired suppression')
        suppressed.append(Suppression(fingerprint, entry['reason'].strip(), expiry.isoformat()))
    return Policy(
        workers=_positive_integer(scan,'workers',4,32),
        max_file_bytes=_positive_integer(scan,'max_file_bytes',1_048_576,16_777_216),
        max_files=_positive_integer(scan,'max_files',10_000,100_000),
        max_total_bytes=_positive_integer(scan,'max_total_bytes',134_217_728,1_073_741_824),
        exclude=tuple(exclude), disabled_rules=tuple(disabled), fail_on=fail_on,
        suppressions=tuple(suppressed))
