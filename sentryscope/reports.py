"""Escaped HTML, JSON, text and SARIF 2.1.0 output without source snippets."""
from html import escape
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import quote

from . import __version__
from .models import finding_order
from .rules import RULES


def document(result,baseline=frozenset(),scan_id=None,project=None):
    data = result.to_dict()
    data['scan_id'],data['project'] = scan_id,project
    data['complete'] = result.complete
    for finding in data['findings']:
        finding['baseline_state'] = 'unchanged' if finding['fingerprint'] in baseline else 'new'
    return data


def sarif(result,baseline=frozenset()):
    rules = sorted(RULES.values(),key=lambda rule:rule.id)
    indexes = {rule.id:index for index,rule in enumerate(rules)}
    report = {
        '$schema':'https://json.schemastore.org/sarif-2.1.0.json',
        'version':'2.1.0','runs':[{
            'columnKind':'unicodeCodePoints',
            'tool':{'driver':{'name':'SentryScope','version':__version__,'rules':[
                {'id':rule.id,'name':rule.title.replace(' ','-'),
                 'shortDescription':{'text':rule.title},
                 'fullDescription':{'text':rule.description},
                 'help':{'text':rule.remediation},
                 'properties':{'tags':['security',rule.cwe],
                               'security-severity':{'critical':'9.0','high':'7.5','medium':'5.0','low':'2.0'}[rule.severity]}}
                for rule in rules]}},
            'invocations':[{'executionSuccessful':result.complete,'toolExecutionNotifications':[
                {'level':'warning','message':{'text':error.message},
                 'descriptor':{'id':error.category}} for error in result.diagnostics]}],
            'results':[]}]}
    for finding in sorted(result.findings,key=finding_order):
        uri = quote(finding.path,safe='/')
        entry = {
            'ruleId':finding.rule_id,'ruleIndex':indexes[finding.rule_id],
            'level':{'critical':'error','high':'error','medium':'warning','low':'note'}[finding.severity],
            'message':{'text':finding.message},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':uri},
                'region':{'startLine':finding.line,'startColumn':finding.column,'endLine':finding.end_line}}}],
            'partialFingerprints':{'sentryscope/structural/v1':finding.fingerprint},
            'baselineState':'unchanged' if finding.fingerprint in baseline else 'new',
            'properties':{'confidence':finding.confidence,'scope':finding.scope}}
        if finding.suppressed:
            entry['suppressions'] = [{'kind':'external','status':'accepted',
                                      'justification':finding.suppression_reason}]
        if finding.trace:
            entry['codeFlows'] = [{'threadFlows':[{'locations':[
                {'location':{'physicalLocation':{'artifactLocation':{'uri':uri},
                    'region':{'startLine':step.line,'startColumn':step.column}},
                    'message':{'text':step.label}}} for step in finding.trace]}]}]
        report['runs'][0]['results'].append(entry)
    return report


def html_report(result,baseline=frozenset(),project='Analysis'):
    def esc(value):
        return escape(str(value),quote=True)
    counts = {severity:sum(f.severity==severity and not f.suppressed for f in result.findings)
              for severity in ('critical','high','medium','low')}
    cards = ''.join(f'<div class="metric"><span>{esc(severity)}</span><strong>{count}</strong></div>'
                    for severity,count in counts.items())
    findings = []
    for finding in sorted(result.findings,key=finding_order):
        rule = RULES[finding.rule_id]
        state = 'suppressed' if finding.suppressed else ('existing' if finding.fingerprint in baseline else 'new')
        trace = ''.join(f'<li><code>{step.line}:{step.column}</code> {esc(step.label)}</li>' for step in finding.trace)
        suppression = f'<p class="muted">Suppression: {esc(finding.suppression_reason)}</p>' if finding.suppressed else ''
        findings.append(f'''<article class="finding" data-severity="{finding.severity}" data-state="{state}">
<div class="row"><span class="badge {finding.severity}">{finding.severity}</span><span>{esc(finding.rule_id)} / {esc(rule.cwe)}</span><span class="state">{state}</span></div>
<h2>{esc(rule.title)}</h2><p class="location">{esc(finding.path)}:{finding.line}:{finding.column} · {esc(finding.scope)}</p>
<p>{esc(finding.message)}</p><p class="fix">{esc(rule.remediation)}</p>{suppression}
<details><summary>Trace and identity</summary><ol>{trace or '<li>No data-flow trace for this rule.</li>'}</ol>
<p class="fingerprint">{finding.fingerprint}</p><p>Confidence: {esc(finding.confidence)}</p></details></article>''')
    diagnostics = ''.join(f'<li>{esc(error.path)}: {esc(error.message)}</li>' for error in result.diagnostics)
    notice = '<aside><strong>Incomplete scan</strong><ul>'+diagnostics+'</ul></aside>' if diagnostics else ''
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SentryScope</title>
<style>:root{color-scheme:light;--ink:#16232f;--muted:#60717d;--paper:#eef2f5;--line:#dce4e9;--accent:#126d67}
*{box-sizing:border-box}body{margin:0;font:15px/1.65 system-ui;background:var(--paper);color:var(--ink)}
header{background:#122c35;color:#edf8f8;padding:45px max(24px,calc((100vw - 1120px)/2))}header small{letter-spacing:.14em;color:#83c6be}
h1{font-size:clamp(30px,4vw,48px);margin:10px 0;overflow-wrap:anywhere}header p{color:#b8d0d2;margin:0}
main{max-width:1168px;padding:28px 24px 70px;margin:auto}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.metric{background:white;border:1px solid var(--line);border-radius:10px;padding:20px}.metric span{text-transform:uppercase;font-size:12px;color:var(--muted)}
.metric strong{display:block;font-size:32px;line-height:1.2;margin-top:8px}.toolbar{display:flex;gap:12px;margin:24px 0;flex-wrap:wrap}
label{display:grid;font-size:12px;color:var(--muted);gap:4px}input,select{font:inherit;padding:10px 12px;background:white;border:1px solid #bccbd4;border-radius:6px;min-width:180px}
input{min-width:280px}.finding{background:white;border:1px solid var(--line);border-radius:10px;padding:25px;margin:16px 0}
.row{display:flex;gap:12px;align-items:center;font-size:12px;color:var(--muted)}.state{margin-left:auto}
.badge{padding:3px 9px;border-radius:4px;text-transform:uppercase;font-weight:700}.high,.critical{background:#fbe1df;color:#963327}.medium{background:#fff0ce;color:#815c11}.low{background:#dfedf7;color:#245578}
h2{font-size:21px;margin:14px 0 2px}.location,.muted{color:var(--muted)}.location,.fingerprint{overflow-wrap:anywhere}
.fix{border-left:3px solid var(--accent);padding-left:14px;color:#28534f}details{border-top:1px solid var(--line);padding-top:14px;margin-top:18px}
summary{cursor:pointer}aside{background:#fff0ce;padding:20px;border-radius:8px;margin:20px 0}.empty{text-align:center;padding:50px;color:var(--muted)}
footer{margin-top:28px;color:var(--muted);font-size:13px}@media(max-width:600px){.metrics{grid-template-columns:repeat(2,1fr)}.finding{padding:18px}input{min-width:0;width:100%}.toolbar label:first-child{width:100%}}
@media print{header{background:white;color:black;padding:0}.toolbar{display:none}main{padding:20px 0}.finding{break-inside:avoid}}
</style></head><body><header><small>SENTRYSCOPE / STATIC ANALYSIS</small><h1>''' + esc(project) + '''</h1><p>Local findings, traceable decisions.</p></header><main>
<section class="metrics">''' + cards + '''</section>''' + notice + '''
<section class="toolbar" aria-label="Finding filters"><label>Search<input id="search" type="search" placeholder="Path, rule or description"></label>
<label>Severity<select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label>
<label>State<select id="state"><option value="">All states</option><option>new</option><option>existing</option><option>suppressed</option></select></label></section>
<p id="visible" aria-live="polite"></p><section id="findings">''' + ''.join(findings) + '''</section>
<footer>''' + esc(result.files_scanned) + ''' files analyzed · ''' + esc(result.bytes_scanned) + ''' bytes · No target code executed.</footer></main>
<script>(()=>{const cards=[...document.querySelectorAll('.finding')];const search=document.getElementById('search');const severity=document.getElementById('severity');const state=document.getElementById('state');
function filter(){let count=0;const term=search.value.toLowerCase();for(const card of cards){const show=(!severity.value||card.dataset.severity===severity.value)&&(!state.value||card.dataset.state===state.value)&&card.textContent.toLowerCase().includes(term);card.hidden=!show;if(show)count++;}document.getElementById('visible').textContent=count+' findings shown';}
for(const control of [search,severity,state])control.addEventListener('input',filter);filter();})();</script></body></html>'''


def render(result,format='json',baseline=frozenset(),scan_id=None,project=None):
    if format=='json':
        return json.dumps(document(result,baseline,scan_id,project),indent=2)+'\n'
    if format=='sarif':
        return json.dumps(sarif(result,baseline),indent=2)+'\n'
    if format=='html':
        return html_report(result,baseline,project or 'Analysis')
    if format!='text':
        raise ValueError('Unknown report format')
    lines = [f'{finding.path}:{finding.line}:{finding.column} {finding.severity.upper()} '
             f'{finding.rule_id} {RULES[finding.rule_id].title}' for finding in result.findings]
    lines.extend(f'{error.path}: INCOMPLETE {error.message}' for error in result.diagnostics)
    lines.append(f'{result.files_scanned} files; {len(result.findings)} findings; complete={result.complete}')
    if scan_id:
        lines.append('Scan: '+scan_id)
    return '\n'.join(lines)+'\n'


def atomic_output(path,text):
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',newline='\n',dir=path.parent,delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
