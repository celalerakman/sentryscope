"""A small abstract value domain for conservative, local taint propagation."""
import ast
from dataclasses import dataclass

from .models import TraceStep


@dataclass(frozen=True)
class Value:
    origins: frozenset[str] = frozenset()
    dynamic: bool = False
    trace: tuple[TraceStep, ...] = ()

    @property
    def tainted(self):
        return bool(self.origins)


EMPTY = Value()


def merge(*values):
    origins = frozenset().union(*(value.origins for value in values))
    steps = sorted({step for value in values for step in value.trace},
                   key=lambda step: (step.line,step.column,step.label))
    return Value(origins, any(value.dynamic for value in values), tuple(steps[:32]))


def step(value, node, label):
    if not value.tainted:
        return value
    location = TraceStep(getattr(node,'lineno',1),getattr(node,'col_offset',0)+1,label)
    return Value(value.origins,value.dynamic,tuple(dict.fromkeys((*value.trace,location)))[:32])


class Names:
    """Track module imports and local shadowing without importing target code."""
    def __init__(self, aliases=None, shadowed=None):
        self.aliases = dict(aliases or {})
        self.shadowed = set(shadowed or ())

    def clone(self):
        return Names(self.aliases,self.shadowed)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            return '<local>.'+node.id if node.id in self.shadowed else node.id
        if isinstance(node, ast.Attribute):
            return self.resolve(node.value)+'.'+node.attr
        return ''

    def bind(self, name, alias=''):
        self.aliases.pop(name,None)
        self.shadowed.add(name)
        if alias:
            self.aliases[name] = alias

    def import_node(self, node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.aliases[alias.asname or alias.name.split('.')[0]] = (
                    alias.name if alias.asname else alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != '*':
                    self.aliases[alias.asname or alias.name] = node.module+'.'+alias.name


def is_source(node, names):
    name = names.resolve(node.func) if isinstance(node,ast.Call) else names.resolve(node)
    if name in ('input','sys.stdin.read','sys.stdin.readline','os.getenv','os.environ.get'):
        return True
    roots = ('request.args','request.form','request.json','request.GET','request.POST',
             'flask.request.args','flask.request.form','flask.request.json')
    return any(name == root or name.startswith(root+'.') for root in roots)


@dataclass(frozen=True)
class Summary:
    parameters: tuple[str, ...]
    returned: Value


def parameters(node):
    args = node.args
    values = [*args.posonlyargs,*args.args,*args.kwonlyargs]
    if args.vararg:
        values.append(args.vararg)
    if args.kwarg:
        values.append(args.kwarg)
    return tuple(arg.arg for arg in values)


class Expressions:
    def __init__(self, env, names, summaries=None, observe=None):
        self.env,self.names = env,names
        self.summaries = summaries or {}
        self.observe = observe or (lambda *args: None)

    def evaluate(self, node):
        if node is None:
            return EMPTY
        if isinstance(node,ast.Constant):
            return EMPTY
        if isinstance(node,ast.Name):
            return self.env.get(node.id,EMPTY)
        if isinstance(node,ast.NamedExpr):
            value = self.evaluate(node.value)
            if isinstance(node.target,ast.Name):
                self.env[node.target.id] = value
            return value
        if isinstance(node,ast.Lambda):
            return EMPTY
        if isinstance(node,ast.Call):
            args = [self.evaluate(arg) for arg in node.args]
            kwargs = {keyword.arg:self.evaluate(keyword.value) for keyword in node.keywords}
            combined = merge(*args,*kwargs.values())
            name = self.names.resolve(node.func)
            summary_name = name.removeprefix('$function.')
            # Method receivers carry flow through .format, .replace, .strip, etc.
            if isinstance(node.func,ast.Attribute):
                combined = merge(combined,self.evaluate(node.func.value))
            if is_source(node,self.names):
                source = TraceStep(node.lineno,node.col_offset+1,'Untrusted input')
                value = Value(frozenset({'source:'+str(node.lineno)}),True,(source,))
            elif summary_name in self.summaries and (name.startswith('$function.') or name == summary_name):
                summary = self.summaries[summary_name]
                bound = {key:args[index] for index,key in enumerate(summary.parameters) if index<len(args)}
                bound.update({key:value for key,value in kwargs.items() if key is not None})
                substitutions = []
                intrinsic = set()
                for origin in summary.returned.origins:
                    if origin.startswith('param:'):
                        substitutions.append(bound.get(origin[6:],EMPTY))
                    else:
                        intrinsic.add(origin)
                intrinsic_trace = tuple(s for s in summary.returned.trace if s.label!='Function parameter')
                value = merge(*substitutions,Value(frozenset(intrinsic),summary.returned.dynamic,intrinsic_trace))
            else:
                # Unknown calls do not imply sanitization.
                value = Value(combined.origins,True,combined.trace)
            self.observe(node,combined,args,kwargs,self.names)
            return step(value,node,'Value returned by call')
        if isinstance(node,ast.Attribute):
            if is_source(node,self.names):
                return Value(frozenset({'source:'+str(node.lineno)}),True,
                             (TraceStep(node.lineno,node.col_offset+1,'Untrusted request field'),))
            return self.evaluate(node.value)
        if isinstance(node,ast.Subscript):
            name = self.names.resolve(node.value)
            if name == 'os.environ' or is_source(node.value,self.names):
                return Value(frozenset({'source:'+str(node.lineno)}),True,
                             (TraceStep(node.lineno,node.col_offset+1,'Untrusted mapping lookup'),))
        if isinstance(node,(ast.ListComp,ast.SetComp,ast.GeneratorExp,ast.DictComp)):
            original = dict(self.env)
            flows = []
            for generator in node.generators:
                incoming = self.evaluate(generator.iter)
                flows.append(incoming)
                for target in ast.walk(generator.target):
                    if isinstance(target,ast.Name):
                        self.env[target.id] = incoming
                flows.extend(self.evaluate(condition) for condition in generator.ifs)
            fields = [node.key,node.value] if isinstance(node,ast.DictComp) else [node.elt]
            result = merge(*flows,*(self.evaluate(value) for value in fields))
            self.env.clear()
            self.env.update(original)
            return result
        children = [self.evaluate(child) for child in ast.iter_child_nodes(node) if isinstance(child,ast.expr)]
        return merge(*children)


class Block:
    """Transfer functions and conservative joins for statements and control flow."""
    def __init__(self, env, names, summaries=None, observe=None, assignment=None):
        self.env,self.names = env,names
        self.summaries = summaries or {}
        self.observe = observe
        self.assignment = assignment or (lambda target,value,node: None)
        self.returns = []

    def expression(self,node):
        return Expressions(self.env,self.names,self.summaries,self.observe).evaluate(node)

    def assign(self,target,value,source):
        if isinstance(target,ast.Name):
            self.env[target.id] = step(value,target,'Assigned value')
            alias = self.names.resolve(source) if isinstance(source,(ast.Name,ast.Attribute)) else ''
            self.names.bind(target.id,alias if '.' in alias and not alias.startswith('<local>') else '')
            self.assignment(target,value,source)
        elif isinstance(target,(ast.Tuple,ast.List)):
            for element in target.elts:
                self.assign(element,value,source)
        elif isinstance(target,(ast.Subscript,ast.Attribute)):
            # A write may update a container subsequently passed to a sink.
            root = target
            while isinstance(root,(ast.Subscript,ast.Attribute)):
                root = root.value
            if isinstance(root,ast.Name):
                self.env[root.id] = merge(self.env.get(root.id,EMPTY),value)

    def branch(self,statements,env=None):
        child = Block(dict(self.env if env is None else env),self.names.clone(),self.summaries,
                      self.observe,self.assignment)
        child.run(statements)
        self.returns.extend(child.returns)
        return child

    def join(self,branches):
        keys = set().union(*(branch.env for branch in branches))
        self.env.clear()
        for key in keys:
            self.env[key] = merge(*(branch.env.get(key,EMPTY) for branch in branches))
        # Conflicting aliases cannot be resolved as a known dangerous builtin.
        names = set().union(*(set(branch.names.aliases)|branch.names.shadowed for branch in branches))
        for name in names:
            aliases = {branch.names.aliases.get(name) for branch in branches}
            if len(aliases)==1 and None not in aliases:
                self.names.aliases[name] = aliases.pop()
            else:
                self.names.bind(name)

    def run(self,statements):
        for node in statements:
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                self.names.import_node(node)
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                self.names.bind(node.name,'$function.'+node.name if not isinstance(node,ast.ClassDef) else '')
                for decorator in node.decorator_list:
                    self.expression(decorator)
            elif isinstance(node,(ast.Assign,ast.AnnAssign)):
                value = self.expression(node.value)
                targets = node.targets if isinstance(node,ast.Assign) else [node.target]
                for target in targets:
                    self.assign(target,value,node.value)
            elif isinstance(node,ast.AugAssign):
                value = merge(self.expression(node.target),self.expression(node.value))
                self.assign(node.target,value,node.value)
            elif isinstance(node,ast.Return):
                self.returns.append(self.expression(node.value))
            elif isinstance(node,ast.If):
                self.expression(node.test)
                self.join([self.branch(node.body),self.branch(node.orelse)])
            elif isinstance(node,(ast.For,ast.AsyncFor,ast.While)):
                before = self.branch([])
                if isinstance(node,ast.While):
                    self.expression(node.test)
                else:
                    value = self.expression(node.iter)
                    self.assign(node.target,value,node.iter)
                loop = self.branch(node.body)
                self.join([before,loop])
                self.run(node.orelse)
            elif isinstance(node,(ast.Try,ast.TryStar)):
                # Handlers may see intermediate state, so merge pre/post body.
                before = self.branch([])
                body = self.branch(node.body)
                merged = {key:merge(before.env.get(key,EMPTY),body.env.get(key,EMPTY))
                          for key in set(before.env)|set(body.env)}
                handlers = [self.branch(handler.body,merged) for handler in node.handlers]
                success = self.branch(node.orelse,body.env)
                self.join([success,*handlers])
                self.run(node.finalbody)
            elif isinstance(node,(ast.With,ast.AsyncWith)):
                for item in node.items:
                    value = self.expression(item.context_expr)
                    if item.optional_vars:
                        self.assign(item.optional_vars,value,item.context_expr)
                self.run(node.body)
            elif isinstance(node,ast.Match):
                value = self.expression(node.subject)
                branches = [self.branch([])]
                for case in node.cases:
                    env = dict(self.env)
                    for pattern in ast.walk(case.pattern):
                        name = getattr(pattern,'name',None)
                        if name:
                            env[name] = value
                    branch = self.branch(case.body,env)
                    branch.expression(case.guard)
                    branches.append(branch)
                self.join(branches)
            else:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child,ast.expr):
                        self.expression(child)


def function_summaries(tree,names,iterations=8):
    functions = {node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    summaries = {name:Summary(parameters(node),EMPTY) for name,node in functions.items()}
    for _ in range(iterations):
        updated = {}
        for name,node in functions.items():
            args = parameters(node)
            env = {arg:Value(frozenset({'param:'+arg}),True,
                            (TraceStep(node.lineno,node.col_offset+1,'Function parameter'),)) for arg in args}
            local_names = names.clone()
            for function_name in functions:
                local_names.bind(function_name,'$function.'+function_name)
            for arg in args:
                local_names.bind(arg)
            block = Block(env,local_names,summaries)
            block.run(node.body)
            updated[name] = Summary(args,merge(*block.returns))
        if updated == summaries:
            break
        summaries = updated
    return summaries
