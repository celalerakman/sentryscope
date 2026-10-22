"""AST rules, import resolution and source-to-sink finding construction."""
import ast
from collections import defaultdict
from dataclasses import replace
import re

from .flow import Block, EMPTY, Names, Value, function_summaries, parameters
from .models import Diagnostic, Finding, TraceStep, digest
from .rules import RULES

SENSITIVE = re.compile(r'(?:^|_)(?:password|passwd|secret|api_key|access_token|private_key|token)(?:$|_)',re.I)
PLACEHOLDER = re.compile(r'^(?:example|dummy|placeholder|changeme|your[-_ ]|test[-_ ]|<|\$\{|redacted)',re.I)
HTTP_CALLS = {'requests.get','requests.post','requests.put','requests.patch','requests.delete',
              'requests.request','httpx.get','httpx.post','urllib.request.urlopen'}
SUBPROCESS = {'subprocess.run','subprocess.call','subprocess.check_call','subprocess.check_output','subprocess.Popen'}
DESERIALIZERS = {'pickle.load','pickle.loads','dill.load','dill.loads','marshal.load','marshal.loads'}


def constant(node,value):
    return isinstance(node,ast.Constant) and node.value is value


def initial_names(tree):
    names = Names()
    for node in tree.body:
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            names.import_node(node)
    return names


def analyze_python(text,path):
    try:
        tree = ast.parse(text,filename=path)
    except (SyntaxError,ValueError,RecursionError):
        return [],[Diagnostic(path,'parse','Python source could not be parsed')]
    analyzer = Analyzer(tree,path)
    try:
        findings=analyzer.run()
        lines=text.splitlines()
        def column(line,byte_column):
            if not 1<=line<=len(lines):
                return byte_column
            prefix=lines[line-1].encode('utf-8')[:byte_column-1]
            return len(prefix.decode('utf-8',errors='ignore'))+1
        return [replace(finding,column=column(finding.line,finding.column),
                        trace=tuple(replace(step,column=column(step.line,step.column)) for step in finding.trace))
                for finding in findings],[]
    except RecursionError:
        return [],[Diagnostic(path,'complexity','AST recursion budget exceeded')]


class Analyzer:
    def __init__(self,tree,path):
        self.tree,self.path = tree,path
        self.names = initial_names(tree)
        self.summaries = function_summaries(tree,self.names)
        self.parents = {child:node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        self.findings = []
        self.seen = set()
        self.occurrences = defaultdict(int)

    def emit(self,rule_id,node,scope,flow=EMPTY,confidence='high'):
        key = (rule_id,node.lineno,node.col_offset,scope)
        if key in self.seen:
            return
        self.seen.add(key)
        rule = RULES[rule_id]
        # AST values enter a one-way fingerprint only. Source snippets and literal
        # credentials never enter report/database fields.
        structural = digest(ast.dump(node,include_attributes=False))
        occurrence_key = (rule_id,scope,structural)
        ordinal = self.occurrences[occurrence_key]
        self.occurrences[occurrence_key] += 1
        fingerprint = digest([self.path,rule_id,scope,structural,ordinal])
        trace = flow.trace
        if flow.tainted:
            sink = TraceStep(node.lineno,node.col_offset+1,'Sensitive operation')
            trace = tuple(dict.fromkeys((*trace,sink)))[:32]
        self.findings.append(Finding(
            rule_id,self.path,node.lineno,node.col_offset+1,getattr(node,'end_lineno',node.lineno),
            scope,rule.description,rule.severity,confidence,fingerprint,trace))

    def observe(self,scope):
        def callback(node,combined,args,kwargs,names):
            name = names.resolve(node.func)
            first = args[0] if args else EMPTY
            keyword_nodes = {item.arg:item.value for item in node.keywords}
            if name in ('eval','exec'):
                self.emit('PY001',node,scope,first)
            if name in ('os.system','os.popen') or (
                    name in SUBPROCESS and constant(keyword_nodes.get('shell'),True)):
                self.emit('PY002',node,scope,first)
            if name.endswith(('.execute','.executemany','.executescript')) and first.tainted:
                self.emit('PY003',node,scope,first,'medium')
            if name in DESERIALIZERS:
                self.emit('PY004',node,scope,first)
            if name in ('yaml.load','yaml.load_all'):
                loader = keyword_nodes.get('Loader') or (node.args[1] if len(node.args)>1 else None)
                resolved = names.resolve(loader)
                if resolved not in ('yaml.SafeLoader','yaml.CSafeLoader'):
                    self.emit('PY005',node,scope,first)
            if ((name in HTTP_CALLS and constant(keyword_nodes.get('verify'),False)) or
                    name == 'ssl._create_unverified_context'):
                self.emit('PY006',node,scope)
            if name in ('hashlib.md5','hashlib.sha1') and not constant(keyword_nodes.get('usedforsecurity'),False):
                self.emit('PY007',node,scope)
            if name == 'tempfile.mktemp':
                self.emit('PY008',node,scope)
            if name in HTTP_CALLS:
                url = args[1] if name=='requests.request' and len(args)>1 else first
                url = kwargs.get('url',url)
                if url.tainted:
                    self.emit('PY009',node,scope,url,'medium')
            if name in ('open','io.open','os.open'):
                filename = kwargs.get('file',first)
                if filename.tainted:
                    self.emit('PY010',node,scope,filename,'medium')
            if name.startswith('random.'):
                parent = self.parents.get(node)
                targets = parent.targets if isinstance(parent,ast.Assign) else (
                    [parent.target] if isinstance(parent,ast.AnnAssign) else [])
                if any(isinstance(target,ast.Name) and SENSITIVE.search(target.id) for target in targets):
                    self.emit('PY011',node,scope)
            if name.endswith('.run') and constant(keyword_nodes.get('debug'),True):
                self.emit('PY013',node,scope,confidence='medium')
            if name=='os.chmod':
                mode = keyword_nodes.get('mode') or (node.args[1] if len(node.args)>1 else None)
                if isinstance(mode,ast.Constant) and type(mode.value) is int and mode.value & 0o002:
                    self.emit('PY014',node,scope)
            if name.endswith(('.extract','.extractall')):
                extraction_filter = keyword_nodes.get('filter')
                if isinstance(extraction_filter,ast.Constant) and extraction_filter.value=='fully_trusted':
                    self.emit('PY015',node,scope,confidence='medium')
        return callback

    def hardcoded(self,node,scope):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets = node.targets if isinstance(node,ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                name = target.id if isinstance(target,ast.Name) else (
                    target.attr if isinstance(target,ast.Attribute) else '')
                if (SENSITIVE.search(name) and isinstance(value,ast.Constant) and
                    isinstance(value.value,str) and len(value.value)>=8 and not PLACEHOLDER.search(value.value)):
                    self.emit('PY012',node,scope,confidence='medium')

    def inspect_block(self,nodes,scope,names,env):
        block = Block(env,names,self.summaries,self.observe(scope))
        block.run(nodes)
        # Stay within the current lexical scope for literal assignment checks.
        def inspect(node):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                return
            self.hardcoded(node,scope)
            for child in ast.iter_child_nodes(node):
                inspect(child)
        for node in nodes:
            inspect(node)

    def run(self):
        self.inspect_block(self.tree.body,'<module>',self.names.clone(),{})
        def functions(nodes,parent_scope=''):
            for node in nodes:
                if isinstance(node,ast.ClassDef):
                    class_scope = parent_scope+'.'+node.name if parent_scope else node.name
                    self.inspect_block(node.body,class_scope,self.names.clone(),{})
                    functions(node.body,class_scope)
                elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    scope = parent_scope+'.'+node.name if parent_scope else node.name
                    args = parameters(node)
                    env = {arg:Value(frozenset({'param:'+arg}),True,
                                    (TraceStep(node.lineno,node.col_offset+1,'Function parameter'),)) for arg in args}
                    names = self.names.clone()
                    for function_name in self.summaries:
                        names.bind(function_name,'$function.'+function_name)
                    for arg in args:
                        names.bind(arg)
                    self.inspect_block(node.body,scope,names,env)
                    functions(node.body,scope)
                else:
                    # Definitions nested in conditional/try blocks remain discoverable.
                    children = [child for child in ast.iter_child_nodes(node) if isinstance(child,ast.stmt)]
                    functions(children,parent_scope)
        functions(self.tree.body)
        return self.findings
