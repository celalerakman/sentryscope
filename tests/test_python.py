import unittest

from sentryscope.python import analyze_python


def analyze(source):
    findings,diagnostics = analyze_python(source,'application.py')
    if diagnostics:
        raise AssertionError(diagnostics)
    return findings


def rules(source):
    return {finding.rule_id for finding in analyze(source)}


class RuleDetection(unittest.TestCase):
    def test_eval_and_exec(self):
        self.assertIn('PY001',rules('eval(input())'))
        self.assertIn('PY001',rules('exec("print(1)")'))

    def test_shadowed_builtin_is_not_reported(self):
        self.assertNotIn('PY001',rules('def eval(value):\n    return value\neval("x")'))
        self.assertNotIn('PY001',rules('def f(eval):\n    return eval("x")'))

    def test_subprocess_import_alias(self):
        source='from subprocess import run as launch\nlaunch(input(), shell=True)'
        self.assertIn('PY002',rules(source))

    def test_subprocess_function_alias(self):
        self.assertIn('PY002',rules('import subprocess\nlaunch=subprocess.run\nlaunch("echo hi",shell=True)'))

    def test_shell_false_is_not_reported(self):
        self.assertNotIn('PY002',rules('import subprocess\nsubprocess.run(["echo",input()],shell=False)'))

    def test_os_system(self):
        self.assertIn('PY002',rules('import os\nos.system(input())'))

    def test_sql_fstring_flow(self):
        source='name=input()\nquery=f"SELECT * FROM users WHERE name={name}"\ncursor.execute(query)'
        findings=[finding for finding in analyze(source) if finding.rule_id=='PY003']
        self.assertEqual(len(findings),1)
        self.assertTrue(any(step.label=='Untrusted input' for step in findings[0].trace))
        self.assertEqual(findings[0].line,3)

    def test_parameterized_sql_is_clean(self):
        self.assertNotIn('PY003',rules('name=input()\ncursor.execute("SELECT * FROM users WHERE name=?",(name,))'))

    def test_reassignment_kills_taint(self):
        self.assertNotIn('PY003',rules('query=input()\nquery="SELECT 1"\ncursor.execute(query)'))

    def test_branch_join_preserves_possible_taint(self):
        source='query="SELECT 1"\nif enabled:\n    query=input()\ncursor.execute(query)'
        self.assertIn('PY003',rules(source))

    def test_loop_join_preserves_zero_iteration_state(self):
        source='query=input()\nfor item in []:\n    query="SELECT 1"\ncursor.execute(query)'
        self.assertIn('PY003',rules(source))

    def test_try_handler_sees_intermediate_flow(self):
        source='query="SELECT 1"\ntry:\n    query=input()\n    fail()\nexcept Exception:\n    cursor.execute(query)'
        self.assertIn('PY003',rules(source))

    def test_with_optional_variable_flow(self):
        self.assertIn('PY010',rules('def read(path):\n    with open(path) as stream:\n        return stream.read()'))

    def test_comprehension_flow(self):
        source='name=input()\nqueries=[x for x in [name]]\ncursor.execute(queries[0])'
        self.assertIn('PY003',rules(source))

    def test_named_expression_flow(self):
        self.assertIn('PY003',rules('if (query:=input()):\n    cursor.execute(query)'))

    def test_function_return_summary(self):
        source='def wrap(value):\n    return "prefix "+value\nquery=wrap(input())\ncursor.execute(query)'
        self.assertIn('PY003',rules(source))

    def test_safe_function_return_does_not_taint_call_site(self):
        source='def fixed(value):\n    return "SELECT 1"\nquery=fixed(input())\ncursor.execute(query)'
        self.assertNotIn('PY003',rules(source))

    def test_summary_keyword_arguments(self):
        source='def wrap(value):\n    return value\nquery=wrap(value=input())\ncursor.execute(query)'
        self.assertIn('PY003',rules(source))

    def test_summary_fixed_point_across_wrappers(self):
        source='def first(value):\n    return second(value)\ndef second(value):\n    return value\ncursor.execute(first(input()))'
        self.assertIn('PY003',rules(source))

    def test_intrinsic_source_return(self):
        source='def read_query():\n    return input()\ncursor.execute(read_query())'
        self.assertIn('PY003',rules(source))

    def test_function_parameters_are_conservative_sources(self):
        self.assertIn('PY003',rules('def query(value):\n    cursor.execute(value)'))

    def test_unknown_calls_are_not_sanitizers(self):
        self.assertIn('PY003',rules('cursor.execute(clean(input()))'))

    def test_method_receiver_format_flow(self):
        self.assertIn('PY003',rules('query="SELECT {}".format(input())\ncursor.execute(query)'))

    def test_async_function_scope(self):
        found=analyze('async def run(value):\n    cursor.execute(value)')
        self.assertEqual(found[0].scope,'run')

    def test_class_method_scope(self):
        found=analyze('class Service:\n    def query(self,value):\n        cursor.execute(value)')
        self.assertEqual(found[0].scope,'Service.query')

    def test_nested_function_scope(self):
        found=analyze('def outer():\n    def inner(value):\n        cursor.execute(value)')
        self.assertEqual(found[0].scope,'outer.inner')

    def test_request_source(self):
        self.assertIn('PY003',rules('from flask import request\ncursor.execute(request.args.get("query"))'))

    def test_environment_source(self):
        self.assertIn('PY003',rules('import os\ncursor.execute(os.environ["QUERY"])'))

    def test_unsafe_deserializer(self):
        self.assertIn('PY004',rules('import pickle as p\np.loads(data)'))

    def test_yaml_safe_loader(self):
        self.assertNotIn('PY005',rules('import yaml\nyaml.load(data,Loader=yaml.SafeLoader)'))
        self.assertNotIn('PY005',rules('from yaml import load,CSafeLoader as Safe\nload(data,Safe)'))

    def test_yaml_default_loader(self):
        self.assertIn('PY005',rules('import yaml\nyaml.load(data)'))

    def test_tls_disabled(self):
        self.assertIn('PY006',rules('import requests as r\nr.get("https://example.test",verify=False)'))
        self.assertNotIn('PY006',rules('import requests\nrequests.get("https://example.test",verify=True)'))

    def test_unverified_ssl_context(self):
        self.assertIn('PY006',rules('from ssl import _create_unverified_context as insecure\ninsecure()'))

    def test_non_security_weak_digest_is_exempt(self):
        self.assertIn('PY007',rules('import hashlib\nhashlib.md5(data)'))
        self.assertNotIn('PY007',rules('import hashlib\nhashlib.md5(data,usedforsecurity=False)'))

    def test_race_prone_tempfile(self):
        self.assertIn('PY008',rules('import tempfile\ntempfile.mktemp()'))
        self.assertNotIn('PY008',rules('import tempfile\ntempfile.mkstemp()'))

    def test_ssrf_flow(self):
        self.assertIn('PY009',rules('import requests\nrequests.get(input())'))
        self.assertIn('PY009',rules('import requests\nrequests.request("GET",input())'))

    def test_url_keyword(self):
        self.assertIn('PY009',rules('import httpx\nhttpx.get(url=input())'))

    def test_path_flow(self):
        self.assertIn('PY010',rules('open(input())'))
        self.assertNotIn('PY010',rules('open("settings.json")'))

    def test_random_is_context_specific(self):
        self.assertIn('PY011',rules('import random\naccess_token=random.random()'))
        self.assertNotIn('PY011',rules('import random\nsample=random.random()'))

    def test_credential_literal_is_not_disclosed(self):
        value='s7Ny2pQ8vL4x9qZ6'
        findings=analyze(f'api_key="{value}"')
        self.assertEqual(findings[0].rule_id,'PY012')
        self.assertNotIn(value,str(findings[0].to_dict()))
        self.assertNotIn('PY012',rules('api_key="example-only-value"'))

    def test_debug_permissions_and_tar(self):
        self.assertIn('PY013',rules('app.run(debug=True)'))
        self.assertIn('PY014',rules('import os\nos.chmod("data",0o777)'))
        self.assertNotIn('PY014',rules('import os\nos.chmod("data",0o640)'))
        self.assertIn('PY015',rules('archive.extractall(filter="fully_trusted")'))
        self.assertNotIn('PY015',rules('archive.extractall(filter="data")'))

    def test_fingerprint_survives_unrelated_line_insertion(self):
        before=analyze('eval(input())')[0]
        after=analyze('# comment\n\neval(input())')[0]
        self.assertEqual(before.fingerprint,after.fingerprint)
        self.assertNotEqual(before.line,after.line)

    def test_repeated_identical_findings_have_distinct_identity(self):
        findings=analyze('eval(input())\neval(input())')
        self.assertEqual(len({finding.fingerprint for finding in findings}),2)

    def test_parse_failure_is_not_a_clean_result(self):
        findings,errors=analyze_python('def :','broken.py')
        self.assertEqual(findings,[])
        self.assertEqual(errors[0].category,'parse')

    def test_unicode_column_offsets(self):
        source='name="é"; eval(input())'
        finding=analyze(source)[0]
        self.assertEqual(finding.column,source.index('eval')+1)


if __name__=='__main__':
    unittest.main()
