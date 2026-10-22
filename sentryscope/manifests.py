"""Offline manifest policy checks; deliberately not a vulnerability database."""
from pathlib import PurePosixPath
import re

from .models import Finding, digest
from .rules import RULES


def finding(rule_id,path,line,identity):
    rule = RULES[rule_id]
    return Finding(rule_id,path,line,1,line,'<manifest>',rule.description,
                   rule.severity,'high',digest([path,rule_id,identity]))


def requirements(text,path):
    results = []
    occurrences = {}
    for number,line in enumerate(text.splitlines(),1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        normalized = line.split(' #',1)[0].strip()
        ordinal = occurrences.get(normalized,0)
        occurrences[normalized] = ordinal+1
        identity = digest([normalized,ordinal])
        if re.search(r'http://',normalized,re.I):
            results.append(finding('DEP002',path,number,identity))
        if normalized.startswith(('-', '--')):
            continue
        declaration = normalized.split(';',1)[0]
        if not re.search(r'==\s*[^\s,*]+',declaration) or '.*' in declaration:
            results.append(finding('DEP001',path,number,identity))
    return results


def dockerfile(text,path):
    results = []
    final_user = None
    stage_line = None
    from_count = 0
    for number,line in enumerate(text.splitlines(),1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        instruction = parts[0].upper()
        if instruction=='FROM' and len(parts)>1:
            image = next((part for part in parts[1:] if not part.startswith('--')),'')
            stage_line,final_user = number,None
            if image != 'scratch' and '@sha256:' not in image:
                results.append(finding('CFG002',path,number,digest([image,from_count])))
            from_count += 1
        elif instruction=='USER' and len(parts)>1:
            final_user = parts[1].split(':',1)[0]
    if stage_line is not None and final_user in (None,'root','0'):
        results.append(finding('CFG001',path,stage_line,'final-stage-user'))
    return results


def analyze_manifest(text,path):
    name = PurePosixPath(path).name
    if name.startswith('requirements') and name.endswith('.txt'):
        return requirements(text,path)
    if name=='Dockerfile' or name.startswith('Dockerfile.'):
        return dockerfile(text,path)
    return []
