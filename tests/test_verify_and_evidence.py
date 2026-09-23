# -*- coding: utf-8 -*-
"""第二轮审计的回归测试：存活验证（subdomain --verify）与取证模式（api evidence）。

覆盖 2026-09-24 自审发现的三个问题：
  - save_evidence 的 host/slug 未清洗会目录穿越（含 ".." 边界）
  - dns_lookup 修改进程级默认超时未恢复
  - run_verify 的文件句柄未用 with 管理
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from mock_server import serve                       # noqa: E402

OUT = os.path.join(ROOT, "out", "_unittest2")
BOGUS = "no-such-host-abcxyz-definitely-invalid.invalid"


def _quiet(fn, *a, **kw):
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        return fn(*a, **kw)


class TestVerifySubs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve(0)
        cls.port = cls.srv.server_address[1]
        os.makedirs(OUT, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_dns_lookup(self):
        from modules.subdomain import dns_lookup
        self.assertTrue(dns_lookup("localhost"))                 # 能解析
        self.assertEqual(dns_lookup(BOGUS), [])                  # 解析不了 → 空

    def test_dns_lookup_restores_default_timeout(self):
        import socket
        from modules.subdomain import dns_lookup
        before = socket.getdefaulttimeout()
        dns_lookup("localhost", timeout=1.0)
        self.assertEqual(socket.getdefaulttimeout(), before, "不能污染进程级默认超时")

    def test_verify_subs_marks_alive(self):
        from modules.subdomain import verify_subs
        rows = verify_subs(["localhost", BOGUS], workers=2, do_http=False)
        by_host = {r["host"]: r for r in rows}
        self.assertTrue(by_host["localhost"]["alive"])
        self.assertFalse(by_host[BOGUS]["alive"])
        self.assertTrue(by_host["localhost"]["ips"])

    def test_http_probe_against_mock(self):
        from modules.subdomain import http_probe
        r = http_probe("127.0.0.1", timeout=5, port=self.port)     # mock 靶站
        self.assertEqual(r.get("status"), 404)
        self.assertTrue(r.get("scheme") in ("https", "http"))

    def test_run_verify_writes_outputs(self):
        from modules.subdomain import run_verify
        out = os.path.join(OUT, "verifycase")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "subdomains.txt"), "w", encoding="utf-8") as f:
            f.write(f"localhost\n{BOGUS}\n")
        rows = _quiet(run_verify, out, do_http=False)
        self.assertEqual(len(rows), 2)
        for fn in ("subdomains_live.json", "subdomains_live.txt"):
            self.assertTrue(os.path.isfile(os.path.join(out, fn)), f"缺少 {fn}")
        live = open(os.path.join(out, "subdomains_live.txt"), encoding="utf-8").read()
        self.assertIn("localhost", live)
        self.assertNotIn(BOGUS, live)
        with open(os.path.join(out, "subdomains_live.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)


class TestEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve(0)
        cls.port = cls.srv.server_address[1]
        cls.out = os.path.join(OUT, "evidencecase")
        os.makedirs(cls.out, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_evidence_written_for_live_hits(self):
        from modules.api_unauth import run_api
        hits = _quiet(run_api, f"http://127.0.0.1:{self.port}/real", self.out)
        live = [h for h in hits if h.get("live")]
        self.assertTrue(live, "real 场景应有存活命中")
        for h in live:
            d = h.get("evidence_dir")
            self.assertTrue(d and os.path.isdir(d), f"未落盘存证: {h['path']}")
            for fn in ("meta.json", "response.snippet.txt", "repro.md"):
                self.assertTrue(os.path.isfile(os.path.join(d, fn)), f"{h['path']} 缺少 {fn}")
            repro = open(os.path.join(d, "repro.md"), encoding="utf-8").read()
            self.assertIn("curl -sk -i", repro)
            meta = json.load(open(os.path.join(d, "meta.json"), encoding="utf-8"))
            self.assertEqual(meta["status"], 200)
            self.assertTrue(meta["live"])
            snippet = open(os.path.join(d, "response.snippet.txt"), encoding="utf-8").read()
            self.assertGreater(len(snippet), 60)

    def test_evidence_dir_cannot_escape_out(self):
        """目录穿越回归：畸形 URL 的 netloc 必须被清洗，落盘不能跑到 out/ 外面。"""
        from modules.api_unauth import save_evidence
        out = os.path.join(OUT, "traversecase")
        os.makedirs(out, exist_ok=True)
        for bad in ("http://../../evil/x", "http://..", "http://%2e%2e/../x"):
            row = {"url": bad, "path": "/../../pwn", "name": "t", "risk": "低",
                   "evidence": "e", "live": True, "recheck": {}}
            try:
                res = _quiet(save_evidence, row, out)
            except Exception:
                continue
            real = os.path.realpath(res["dir"])
            self.assertTrue(real.startswith(os.path.realpath(out) + os.sep),
                            f"目录穿越: {bad} → {real}")


if __name__ == "__main__":
    unittest.main()
