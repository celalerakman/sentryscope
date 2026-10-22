"""Bounded file discovery and concurrent analysis without executing target code."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from fnmatch import fnmatch
import io
import os
from pathlib import Path
import stat
import time
import tokenize

from .config import Policy
from .manifests import analyze_manifest
from .models import Diagnostic, ScanResult, finding_order
from .python import analyze_python


@dataclass(frozen=True)
class Source:
    absolute: Path
    relative: str
    size: int
    modified: int
    inode: int
    device: int


def supported(name):
    return (name.endswith('.py') or (name.startswith('requirements') and name.endswith('.txt'))
            or name=='Dockerfile' or name.startswith('Dockerfile.'))


def excluded(relative,patterns):
    parts = relative.split('/')
    return any(fnmatch(relative,pattern) or any(fnmatch(part,pattern) for part in parts)
               for pattern in patterns)


def discover(root,policy):
    sources,diagnostics = [],[]
    skipped,total = 0,0
    def walk_error(error):
        diagnostics.append(Diagnostic('<discovery>','io','A directory could not be read'))
    for directory,dirs,files in os.walk(root,followlinks=False,onerror=walk_error):
        safe_dirs = []
        for name in sorted(dirs):
            child = Path(directory)/name
            relative = child.relative_to(root).as_posix()
            if child.is_symlink() or excluded(relative,policy.exclude):
                continue
            if getattr(child.lstat(),'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0):
                continue
            safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            if not supported(name):
                continue
            child = Path(directory)/name
            relative = child.relative_to(root).as_posix()
            if excluded(relative,policy.exclude) or child.is_symlink():
                skipped += 1
                continue
            try:
                info = child.lstat()
                if not stat.S_ISREG(info.st_mode):
                    skipped += 1
                    continue
                if getattr(info,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0):
                    skipped += 1
                    continue
                if info.st_size > policy.max_file_bytes:
                    diagnostics.append(Diagnostic(relative,'budget','File size budget exceeded'))
                    skipped += 1
                    continue
                if len(sources)>=policy.max_files or total+info.st_size>policy.max_total_bytes:
                    diagnostics.append(Diagnostic('<discovery>','budget','Scan size or file count budget exceeded'))
                    return sources,diagnostics,skipped
                sources.append(Source(child,relative,info.st_size,info.st_mtime_ns,info.st_ino,info.st_dev))
                total += info.st_size
            except OSError:
                diagnostics.append(Diagnostic(relative,'io','File metadata could not be read'))
    return sources,diagnostics,skipped


def read_source(source,root,limit):
    if not source.absolute.resolve().is_relative_to(root):
        raise ValueError('File escaped scan root')
    flags = os.O_RDONLY | getattr(os,'O_BINARY',0) | getattr(os,'O_NOFOLLOW',0)
    descriptor = os.open(source.absolute,flags)
    with os.fdopen(descriptor,'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Not a regular source file')
        if (before.st_ino,before.st_dev,before.st_mtime_ns,before.st_size) != (
                source.inode,source.device,source.modified,source.size):
            raise ValueError('Source changed before reading')
        data = stream.read(limit+1)
        after = os.fstat(stream.fileno())
        if len(data)>limit or (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            raise ValueError('Source changed while reading')
    if not source.absolute.resolve().is_relative_to(root):
        raise ValueError('File escaped scan root')
    if source.absolute.suffix=='.py':
        encoding,_ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return data.decode(encoding),len(data)
    return data.decode('utf-8-sig'),len(data)


def analyze_source(source,root,policy):
    try:
        text,size = read_source(source,root,policy.max_file_bytes)
        if source.absolute.suffix=='.py':
            findings,diagnostics = analyze_python(text,source.relative)
        else:
            findings,diagnostics = analyze_manifest(text,source.relative),[]
        return findings,diagnostics,size
    except (OSError,ValueError,UnicodeError,SyntaxError,LookupError):
        return [],[Diagnostic(source.relative,'read','Source could not be read consistently')],None
    except (RecursionError,MemoryError):
        return [],[Diagnostic(source.relative,'complexity','Analysis resource budget exceeded')],None


def scan(root,policy=None):
    policy = policy or Policy()
    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        raise ValueError('Scan root must be a regular directory')
    root = requested.resolve()
    started = time.perf_counter()
    sources,diagnostics,skipped = discover(root,policy)
    result = ScanResult(diagnostics=diagnostics,files_skipped=skipped,policy_digest=policy.fingerprint)
    suppressions = {item.fingerprint:item for item in policy.suppressions}
    with ThreadPoolExecutor(max_workers=policy.workers,thread_name_prefix='sentryscope') as executor:
        outcomes = executor.map(lambda source:analyze_source(source,root,policy),sources)
        for findings,errors,size in outcomes:
            result.files_scanned += int(size is not None)
            result.bytes_scanned += size or 0
            result.diagnostics.extend(errors)
            for finding in findings:
                if finding.rule_id in policy.disabled_rules:
                    continue
                suppression = suppressions.get(finding.fingerprint)
                if suppression:
                    finding = replace(finding,suppressed=True,suppression_reason=suppression.reason)
                result.findings.append(finding)
    result.findings.sort(key=finding_order)
    result.diagnostics.sort(key=lambda item:(item.path,item.category,item.message))
    result.duration_seconds = round(time.perf_counter()-started,6)
    return result
