import unittest
from sentryscope.manifests import analyze_manifest


class Manifests(unittest.TestCase):
    def ids(self,text,path):
        return [finding.rule_id for finding in analyze_manifest(text,path)]

    def test_exact_pin_and_hash(self):
        self.assertEqual(self.ids('package==1.2.3 --hash=sha256:abc','requirements.txt'),[])

    def test_range_and_wildcard(self):
        self.assertEqual(self.ids('package>=1\nother==1.*','requirements-dev.txt'),['DEP001','DEP001'])

    def test_http_dependency_source(self):
        self.assertIn('DEP002',self.ids('--index-url http://packages.example.test/simple','requirements.txt'))

    def test_comments_and_include(self):
        self.assertEqual(self.ids('# comment\n-r base.txt\n','requirements.txt'),[])

    def test_no_raw_manifest_credentials(self):
        findings=analyze_manifest('pkg @ http://user:private@packages.example.test/a.whl','requirements.txt')
        self.assertNotIn('private',str([finding.to_dict() for finding in findings]))

    def test_root_default(self):
        self.assertIn('CFG001',self.ids('FROM python:3.12\nRUN echo ok','Dockerfile'))

    def test_nonroot_digest(self):
        self.assertEqual(self.ids('FROM python@sha256:'+'a'*64+'\nUSER 10001:10001','Dockerfile'),[])

    def test_final_stage_user_reset(self):
        rules=self.ids('FROM python:3.12 AS build\nUSER worker\nFROM python:3.12\nCMD ["python"]','Dockerfile')
        self.assertEqual(rules.count('CFG002'),2)
        self.assertIn('CFG001',rules)

    def test_root_explicit(self):
        self.assertIn('CFG001',self.ids('FROM scratch\nUSER 0:0','Dockerfile'))

    def test_non_manifest_is_ignored(self):
        self.assertEqual(self.ids('package>=1','notes.txt'),[])
