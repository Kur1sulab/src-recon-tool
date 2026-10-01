# -*- coding: utf-8 -*-
"""fix1 第 1 轮修复回归（Python 侧，与 Go 用例同表钉 parity）：
  1. make_outdir 清洗（与 engine-go MakeOutdir 逐字符同规则）：
     反斜杠穿越 / Windows 非法字符 / ".." 纯穿越锚 / 尾点归一
  2. netutil.safe_filename Windows 保留设备名（与 Go SafeFilename 同步）
  3. subdomain._from_crtsh 控制字符清洗（与 Go collectNames 同步）
"""
import os
import shutil
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import recon  # noqa: E402
from modules import netutil, subdomain  # noqa: E402


class MakeOutdirTest(unittest.TestCase):
    def setUp(self):
        self.cwd = os.getcwd()
        self.tmp = os.path.join(ROOT, "out_fix1_test_tmp")
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.makedirs(self.tmp, exist_ok=True)
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sanitized_names_match_go(self):
        cases = {
            "example.com": "example.com",
            "http://x.com/a?api_key=TOPSECRET&b=1": "http_x.com_a_api_key_TOPSECRET_b_1",
            "..\\..\\trav": "_.._trav",
            "..": "unknown",
            "../..": "_",
            ".": "unknown",
            "": "unknown",
            "x.com.": "x.com",
        }
        for target, want in cases.items():
            out = recon.make_outdir(target)
            base = os.path.basename(out)
            self.assertEqual(base, want, "target=%r" % target)
            self.assertTrue(os.path.isdir(out))
            # 一律限制在 ./out/ 之内
            self.assertEqual(os.path.dirname(os.path.abspath(out)),
                             os.path.abspath(os.path.join(self.tmp, "out")))


class SafeFilenameDeviceTest(unittest.TestCase):
    def test_reserved_stems_get_suffix(self):
        cases = {
            "con.txt": "con_.txt",
            "CON": "CON_",
            "com1.zip": "com1_.zip",
            "nul": "nul_",
            "LPT9.log": "LPT9_.log",
            "aux": "aux_",
            "config.txt": "config.txt",
            "conny.txt": "conny.txt",
            "bad/name?.txt": "bad_name_.txt",
        }
        for inp, want in cases.items():
            self.assertEqual(netutil.safe_filename(inp), want, "input=%r" % inp)


class CrtShControlCharTest(unittest.TestCase):
    def test_control_chars_stripped(self):
        import json as _json
        # 用 json.dumps 生成合法 JSON：值里带真实控制字符 \x01\x02（crt.sh
        # 实测污染形态），清洗后应得同名可入列子域。
        fixture = _json.dumps(
            [{"name_value": "\x01\x02ctl.stub.example.com\nOK.stub.example.com"}])

        class FakeResp(dict):
            pass

        orig_fetch = subdomain.netutil.fetch
        orig_check = subdomain.netutil.check_http_url
        subdomain.netutil.check_http_url = lambda u, allow_private=False: u
        subdomain.netutil.fetch = lambda url, timeout=30, **kw: {
            "ok": True, "status": 200, "body": fixture}
        try:
            got = subdomain._from_crtsh("stub.example.com")
        finally:
            subdomain.netutil.fetch = orig_fetch
            subdomain.netutil.check_http_url = orig_check
        self.assertEqual(got, ["ctl.stub.example.com", "ok.stub.example.com"])


if __name__ == "__main__":
    unittest.main()
