#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patchdiff 模块测试（unittest，pytest 亦可收集）。"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from modules.patchdiff import run_patchdiff, emit_rule  # noqa: E402


def _git(repo, *args):
    env = os.environ.copy()
    env.update({'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t',
                'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t'})
    subprocess.run(['git'] + list(args), cwd=repo, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)


class PatchdiffTest(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix='pdtest-')
        _git(self.repo, 'init', '-q')
        # 漏洞版本：SQL 拼接 + 命令执行
        with open(os.path.join(self.repo, 'app.py'), 'w') as f:
            f.write('def q(uid):\n    return "SELECT * FROM u WHERE id=" + uid\n')
        _git(self.repo, 'add', '.')
        _git(self.repo, 'commit', '-qm', 'init')
        # 修复版本：参数化查询 + 整数化
        with open(os.path.join(self.repo, 'app.py'), 'w') as f:
            f.write('def q(uid):\n    uid = int(uid)\n    return cursor.execute("SELECT * FROM u WHERE id=?", (uid,))\n')
        _git(self.repo, 'add', '.')
        _git(self.repo, 'commit', '-qm', 'fix: sql injection in q()')

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_finds_security_hunk(self):
        out = tempfile.mkdtemp(prefix='pdout-')
        res = run_patchdiff(self.repo, limit=5, outdir=out, quiet=True)
        self.assertTrue(res['ok'], res)
        self.assertGreaterEqual(len(res['commits']), 1)
        self.assertGreaterEqual(len(res['hunks']), 1)
        joined_fix = ' '.join(x for h in res['hunks'] for x in h['fix'])
        self.assertTrue(any(k in joined_fix for k in ('参数化查询', 'SQL 转义', '整数化')),
                        f'未识别修复信号: {joined_fix}')
        joined_vuln = ' '.join(x for h in res['hunks'] for x in h['vuln'])
        self.assertTrue(joined_vuln, '未识别漏洞写法痕迹')
        self.assertTrue(os.path.exists(res['json']))

    def test_emit_rule(self):
        rows = [{'removed': ['    return "SELECT * FROM u WHERE id=" + uid']}]
        path = os.path.join(tempfile.mkdtemp(prefix='pdrule-'), 'v.yaml')
        emit_rule(rows, path)
        txt = open(path, encoding='utf-8').read()
        self.assertIn('rules:', txt)
        self.assertIn('pattern-regex', txt)
        self.assertIn('SELECT', txt)

    def test_not_a_git_repo(self):
        d = tempfile.mkdtemp(prefix='nogit-')
        res = run_patchdiff(d, quiet=True)
        self.assertFalse(res['ok'])
        shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
