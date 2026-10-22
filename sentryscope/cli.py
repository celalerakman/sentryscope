"""Command interface with explicit finding, input-error and audit exit statuses."""
import argparse
from dataclasses import asdict
import getpass
import json
from pathlib import Path
import sqlite3
import sys

from . import __version__
from .baseline import export_baseline, load_baseline
from .config import load_policy
from .models import Diagnostic, RANK, ScanResult
from .reports import atomic_output, render
from .rules import RULES
from .scanner import scan
from .store import Store


def parser():
    root = argparse.ArgumentParser(prog='sentryscope',description='Local Python static analysis and finding history')
    root.add_argument('--version',action='version',version=__version__)
    commands = root.add_subparsers(dest='command',required=True)
    scanning = commands.add_parser('scan',help='Analyze a local directory without executing it')
    scanning.add_argument('target',type=Path)
    scanning.add_argument('--policy',type=Path)
    scanning.add_argument('--project')
    scanning.add_argument('--baseline',type=Path)
    scanning.add_argument('--fail-on',choices=tuple(RANK))
    scanning.add_argument('--no-store',action='store_true')
    scanning.add_argument('--format',choices=('text','json','html','sarif'),default='text')
    scanning.add_argument('--output',type=Path)
    history = commands.add_parser('history',help='List stored scan snapshots')
    history.add_argument('--project')
    show = commands.add_parser('show',help='Inspect findings with current triage state')
    show.add_argument('scan_id')
    show.add_argument('--status',choices=('open','reviewing','accepted','resolved'))
    comparison = commands.add_parser('diff',help='Compare fingerprints in two scans')
    comparison.add_argument('before')
    comparison.add_argument('after')
    triage = commands.add_parser('triage',help='Record a reasoned finding state transition')
    triage.add_argument('fingerprint')
    triage.add_argument('--project',required=True)
    triage.add_argument('--status',choices=('open','reviewing','accepted','resolved'),required=True)
    triage.add_argument('--version',type=int,required=True)
    triage.add_argument('--actor',default=getpass.getuser())
    triage.add_argument('--reason',required=True)
    audit = commands.add_parser('audit',help='Read or verify the audit chain')
    audit.add_argument('--verify',action='store_true')
    backup = commands.add_parser('backup',help='Create a consistent database snapshot')
    backup.add_argument('destination',type=Path)
    baseline = commands.add_parser('baseline',help='Export a fingerprint baseline from a stored scan')
    baseline.add_argument('scan_id')
    baseline.add_argument('--output',type=Path,required=True)
    report = commands.add_parser('report',help='Render a stored scan')
    report.add_argument('scan_id')
    report.add_argument('--format',choices=('text','json','html','sarif'),default='html')
    report.add_argument('--output',type=Path,required=True)
    commands.add_parser('rules',help='List built-in rules and remediation')
    for command in commands.choices.values():
        if command.prog.endswith(' rules'):
            continue
        command.add_argument('--database',type=Path,default=Path('runtime/sentryscope.sqlite'))
    return root


def _json(value):
    print(json.dumps(value,indent=2))


def _stored_result(snapshot):
    summary = dict(snapshot['summary'])
    summary.pop('schema_version',None)
    summary['diagnostics'] = [Diagnostic(**item) for item in summary.get('diagnostics',[])]
    return ScanResult(findings=snapshot['findings'],**summary)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command=='rules':
            _json([asdict(rule) for rule in RULES.values()])
            return 0
        if args.command=='scan':
            policy = load_policy(args.policy)
            project = args.project or args.target.resolve().name
            baseline = load_baseline(args.baseline,project,policy.fingerprint) if args.baseline else frozenset()
            result = scan(args.target,policy)
            scan_id = None
            if not args.no_store:
                with Store(args.database) as store:
                    scan_id = store.save(project,result)
            output = render(result,args.format,baseline,scan_id,project)
            if args.output:
                atomic_output(args.output,output)
            else:
                sys.stdout.write(output)
            if not result.complete:
                return 2
            threshold = args.fail_on or policy.fail_on
            return int(any(not finding.suppressed and finding.fingerprint not in baseline
                           and RANK[finding.severity]>=RANK[threshold] for finding in result.findings))
        with Store(args.database) as store:
            if args.command=='history':
                _json(store.scans(args.project))
            elif args.command=='show':
                _json(store.findings(args.scan_id,args.status))
            elif args.command=='diff':
                result = store.compare(args.before,args.after)
                _json(result)
                return 0 if result['complete'] else 2
            elif args.command=='triage':
                _json(store.transition(args.project,args.fingerprint,args.status,args.version,args.actor,args.reason))
            elif args.command=='audit':
                if args.verify:
                    valid = store.verify_audit()
                    _json({'valid':valid})
                    return 0 if valid else 3
                _json(store.audit())
            elif args.command=='backup':
                args.destination.parent.mkdir(parents=True,exist_ok=True)
                store.backup(args.destination)
                _json({'backup':str(args.destination)})
            elif args.command=='baseline':
                snapshot = store.get(args.scan_id)
                if snapshot['summary'].get('diagnostics'):
                    raise ValueError('Cannot baseline an incomplete scan')
                value = export_baseline(snapshot['project'],snapshot['findings'],snapshot['summary']['policy_digest'])
                atomic_output(args.output,json.dumps(value,indent=2)+'\n')
            elif args.command=='report':
                snapshot = store.get(args.scan_id)
                atomic_output(args.output,render(_stored_result(snapshot),args.format,
                                                scan_id=args.scan_id,project=snapshot['project']))
        return 0
    except (OSError,ValueError,TypeError,sqlite3.Error) as error:
        print('sentryscope: '+str(error),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
