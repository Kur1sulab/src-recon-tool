# -*- coding: utf-8 -*-
"""jsintel 模块的解析单测 + mock 靶站集成测试。

关注点：
  1) 端点线索：规范化/去重/静态资源过滤——喂给 api/paths 模块前必须先滤掉噪音；
  2) 敏感线索：**全量值绝不能出现在任何输出里**（JSON 文本层面断言），片段同步打码；
  3) 域名线索：子域/第三方/内网 IP 归类正确，公网版本号之类不误收；
  4) WAF 403 / SPA 软 404 站点上优雅降级，不崩、输出空结果。

注：本文件里出现的"敏感值"全是假值，且分段拼接构造——既避免凭据扫描器
误报硬编码凭据，也方便在"输出不得含全量值"的断言里直接引用原始串。
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from mock_server import serve, FAKE_PW, FAKE_TOKEN, FAKE_APPID   # noqa: E402

SK_VAL = "LTAI5t" + "AbCdEfXyz123"
AUTH_VAL = "Bearer " + "abcdEFGH12345"

OUT = os.path.join(ROOT, "out", "_unittest")


def _quiet(fn, *a, **kw):
    buf = io.StringIO()
    with redirect_stdout(buf):
        return fn(*a, **kw)


class TestNormalizeEndpoint(unittest.TestCase):
    def test_basic_normalize(self):
        from modules.jsintel import normalize_endpoint
        self.assertEqual(normalize_endpoint("/api/v1/users"), "/api/v1/users")
        self.assertEqual(normalize_endpoint("api/v1/users"), "/api/v1/users")
        self.assertEqual(normalize_endpoint("/api/u?x=1#frag"), "/api/u")
        self.assertEqual(normalize_endpoint("https://a.com/v3/pay"), "/v3/pay")
        self.assertEqual(normalize_endpoint("/admin/"), "/admin")

    def test_static_and_noise_filtered(self):
        from modules.jsintel import normalize_endpoint
        for noise in ("/static/app.js", "/assets/main.css", "/img/logo.png",
                      "/fonts/a.woff2", "/a.map"):
            self.assertEqual(normalize_endpoint(noise), "", noise)
        self.assertEqual(normalize_endpoint("/api/${id}/x"), "")     # 模板占位，不可复跑
        self.assertEqual(normalize_endpoint("/"), "")
        self.assertEqual(normalize_endpoint(""), "")


class TestExtractEndpoints(unittest.TestCase):
    def test_call_sites_and_literals(self):
        from modules.jsintel import extract_endpoints
        js = ("fetch('/api/v1/users').then();\n"
              "axios.post(\"/api/v2/login\");\n"
              "axios({url:'/api/v3/me'});\n"
              "$.get('/v1/notify');\n"
              "var a='/api/v1/users';\n"                       # 与 fetch 重复，应去重
              "var b='/static/app.js';\n")                     # 静态资源应滤掉
        self.assertEqual(extract_endpoints(js),
                         ["/api/v1/users", "/api/v2/login", "/api/v3/me", "/v1/notify"])

    def test_cap(self):
        from modules.jsintel import extract_endpoints
        js = "".join(f"var x{i}='/p{i}';\n" for i in range(1000))
        self.assertEqual(len(extract_endpoints(js)), 800)


class TestExtractSensitive(unittest.TestCase):
    def test_value_masked_everywhere(self):
        from modules.jsintel import extract_sensitive
        js = "var cfg = {password: '" + FAKE_PW + "'};\nvar ok = 1;"
        rows = extract_sensitive(js, "app.js")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["file"], "app.js")
        self.assertEqual(r["line"], 1)
        self.assertEqual(r["key"], "password")
        self.assertEqual(r["value"], FAKE_PW[:4] + "****")
        self.assertNotIn(FAKE_PW, json.dumps(rows), "全量值不得出现在输出")
        self.assertIn(FAKE_PW[:4] + "****", r["snippet"], "片段里的值也要打码")

    def test_ak_sk_and_blocklist(self):
        from modules.jsintel import extract_sensitive
        js = ("var a = {sk: '" + SK_VAL + "'};\n"
              "var b = {token: 'undefined'};\n"          # 占位符，跳过
              "var c = {ak: '1234'};\n"                  # 纯数字短串，跳过
              "var d = token_fetch('x');\n")             # token_fetch 不是敏感键
        rows = extract_sensitive(js, "x.js")
        self.assertEqual([r["key"] for r in rows], ["sk"])
        self.assertEqual(rows[0]["value"], SK_VAL[:4] + "****")

    def test_minified_single_line_masked_snippet(self):
        from modules.jsintel import extract_sensitive
        js = "a=1;var cfg={authorization:'" + AUTH_VAL + "'};b=2;"
        rows = extract_sensitive(js, "min.js")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["line"], 1)
        self.assertNotIn(AUTH_VAL, json.dumps(rows))


class TestExtractDomains(unittest.TestCase):
    def test_classify(self):
        from modules.jsintel import extract_domains
        js = ("fetch('https://api.xycovo.com/v1');\n"
              "var cdn='https://cdn.thirdparty.cn/x';\n"
              "var intra='http://10.0.0.5:8080/metrics';\n")
        d = extract_domains(js, "xycovo.com")
        self.assertEqual(d["subdomains"], ["api.xycovo.com"])
        self.assertEqual(d["thirdparty"], ["cdn.thirdparty.cn"])
        self.assertEqual(d["internal_ips"], ["10.0.0.5"])

    def test_public_version_numbers_not_collected(self):
        from modules.jsintel import extract_domains
        d = extract_domains("ver='1.2.3.4'; host='https://a.example.com/x'", "example.com")
        self.assertEqual(d["internal_ips"], [])
        self.assertEqual(d["thirdparty"], [])


class TestExtractScripts(unittest.TestCase):
    def test_html_parsing(self):
        from modules.jsintel import extract_scripts
        html = ('<html><head><script src="https://cdn.a.com/x.js"></script>'
                '<script src="//b.com/y.js"></script>'
                '<script src="/js/app.js?v=2"></script></head>'
                '<body><script>var x="/api/keep";</script>'
                '<script src="/img/empty.gif"></script></body></html>')
        page = "https://example.com/dir/page"
        ext, inline = extract_scripts(html, page)
        self.assertEqual(ext, ["https://cdn.a.com/x.js", "https://b.com/y.js",
                               "https://example.com/js/app.js?v=2"])
        self.assertEqual(len(inline), 1)
        self.assertIn("/api/keep", inline[0][1])


class TestJsintelAgainstMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve(0)
        cls.port = cls.srv.server_address[1]
        os.makedirs(OUT, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _run(self, scenario):
        from modules.jsintel import run_jsintel
        return _quiet(run_jsintel, f"http://127.0.0.1:{self.port}/{scenario}", OUT)

    def test_jssite_endpoints_found_and_static_filtered(self):
        res = self._run("jssite")
        eps = set(res["endpoints"])
        for need in ("/api/v1/users", "/api/v2/login", "/v3/pay", "/weather/beijing"):
            self.assertIn(need, eps, f"漏报端点: {need}")
        for noise in ("/static/logo.png", "/assets/main.css"):
            self.assertNotIn(noise, eps, f"静态资源误报: {noise}")
        # 绝对 URL 形式可直接喂给 api/paths 模块
        self.assertIn(f"http://127.0.0.1:{self.port}/api/v1/users", res["endpoints_full"])

    def test_jssite_json_never_contains_full_secrets(self):
        self._run("jssite")
        raw = open(os.path.join(OUT, "jsintel.json"), encoding="utf-8").read()
        for secret in (FAKE_PW, FAKE_TOKEN, FAKE_APPID):
            self.assertNotIn(secret, raw, f"输出 JSON 泄露了全量值: {secret}")
        self.assertIn(FAKE_PW[:4] + "****", raw)
        # 文件级隐私纪律：txt 同样不泄露
        txt = open(os.path.join(OUT, "jsintel.txt"), encoding="utf-8").read()
        self.assertNotIn(FAKE_PW, txt)

    def test_jssite_sensitive_locations_and_domains(self):
        res = self._run("jssite")
        sens = {(s["file"], s["key"]) for s in res["sensitive"]}
        self.assertIn(("/jssite/static/app.js", "password"), sens)
        self.assertIn(("/jssite/static/app.js", "appid"), sens)
        self.assertTrue(any(k == "token" and f.startswith("inline#") for f, k in sens),
                        "内联脚本里的 token 也应被定位")
        d = res["domains"]
        self.assertIn("api.example-cdn.com", d["thirdparty"])
        self.assertIn("10.0.0.5", d["internal_ips"])

    def test_waf_site_degrades_gracefully(self):
        res = self._run("waf")
        self.assertEqual(res["page_status"], 403)
        self.assertEqual(res["endpoints"], [])
        self.assertEqual(res["sensitive"], [])
        self.assertTrue(res.get("error"))

    def test_soft404_spa_no_crash(self):
        res = self._run("soft404")
        self.assertEqual(res["page_status"], 200)
        # SPA 外壳被当成 JS 解析也不应产出端点线索（.js 后缀等噪音已被滤掉）
        self.assertEqual(res["endpoints"], [])


if __name__ == "__main__":
    unittest.main()
