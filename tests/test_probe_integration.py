# -*- coding: utf-8 -*-
"""集成测试：把 mock 靶站起在随机端口上，验证 api/paths 模块"不误报、不漏报"。

这是 2026-09-24 审计的固化：审计时发现 SPA 软 404 / 全局 403 / 统一跳转
会让 paths 报满屏假存活、JSON 软 404 会让 api 误报，修复后这些场景必须为 0。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from mock_server import serve, TRUE_POSITIVES   # noqa: E402

OUT = os.path.join(ROOT, "out", "_unittest")


def _quiet(fn, *a, **kw):
    """跑模块但吞掉它的 print（保持测试输出干净），返回结果。"""
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        return fn(*a, **kw)


class TestProbeAgainstMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve(0)                       # 随机空闲端口
        cls.port = cls.srv.server_address[1]
        os.makedirs(OUT, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _scenario(self, name):
        return f"http://127.0.0.1:{self.port}/{name}"

    def _api(self, scenario):
        from modules.api_unauth import run_api
        return _quiet(run_api, self._scenario(scenario), OUT)

    def _paths(self, scenario):
        from modules.paths import run_paths
        return _quiet(run_paths, self._scenario(scenario), OUT)

    # ── 误报陷阱：四个场景都必须零命中 ──
    def test_soft404_spa_has_no_false_positives(self):
        self.assertEqual(len(self._api("soft404")), 0)
        self.assertEqual(len(self._paths("soft404")), 0)

    def test_json_soft404_has_no_false_positives(self):
        self.assertEqual(len(self._api("api404")), 0)
        self.assertEqual(len(self._paths("api404")), 0)

    def test_uniform_403_waf_has_no_false_positives(self):
        self.assertEqual(len(self._api("waf")), 0)
        self.assertEqual(len(self._paths("waf")), 0)

    def test_redirect_to_login_has_no_false_positives(self):
        self.assertEqual(len(self._api("loginredirect")), 0)
        self.assertEqual(len(self._paths("loginredirect")), 0)

    # ── 对照组：普通 404 站点，本来就不该有命中 ──
    def test_plain_404_site(self):
        self.assertEqual(len(self._api("empty")), 0)
        self.assertEqual(len(self._paths("empty")), 0)

    # ── 真阳性：真实暴露必须被检出，且存活复验通过 ──
    def test_real_exposures_are_detected_and_live(self):
        hits = self._api("real")
        got = {h["path"] for h in hits}
        for need in ("/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/env", "/actuator/heapdump"):
            self.assertIn(need, got, f"漏报: {need}")
        self.assertTrue(all(h.get("live") for h in hits), "命中项都应通过存活复验")

    def test_real_paths_are_detected(self):
        alive = self._paths("real")
        got = {a["path"] for a in alive}
        for need in ("/.env", "/robots.txt", "/actuator"):
            self.assertIn(need, got, f"漏报: {need}")
        self.assertTrue(all(a.get("verified") for a in alive))

    # ── 审计基线自检 ──
    def test_baseline_kinds(self):
        from modules import netutil
        self.assertEqual(netutil.baseline(self._scenario("soft404"))["kind"], "soft404")
        self.assertEqual(netutil.baseline(self._scenario("waf"))["kind"], "uniform403")
        self.assertEqual(netutil.baseline(self._scenario("empty"))["kind"], "normal")

    def test_verify_live_flags_unstable(self):
        from modules import netutil
        v = netutil.verify_live(self._scenario("real") + "/v3/api-docs", tries=2, expect_body='"openapi"')
        self.assertTrue(v["live"])
        v2 = netutil.verify_live(self._scenario("real") + "/nothing-here", tries=2, expect_body='"openapi"')
        self.assertFalse(v2["live"])


if __name__ == "__main__":
    unittest.main()
