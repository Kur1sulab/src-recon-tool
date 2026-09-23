# -*- coding: utf-8 -*-
"""新增模块的解析/判定逻辑单测（离线，不依赖网络）。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)


class TestIPDetect(unittest.TestCase):
    def test_is_ip(self):
        from recon import is_ip
        self.assertTrue(is_ip("47.100.49.228"))
        self.assertTrue(is_ip("2001:db8::1"))
        self.assertFalse(is_ip("example.com"))
        self.assertFalse(is_ip("999.1.1.1"))


class TestReverseParse(unittest.TestCase):
    def test_parse_hackertarget(self):
        from modules.reverse_ip import parse_hackertarget
        raw = ("xycovo.com\n"
               "www.xycovo.com\n"
               "0.0.d.5.9.6.0.7.4.0.1.0.0.2.ip6.arpa\n"
               "not a domain\n"
               "api.example.com.\n"
               "\n"
               "XYCOVO.COM\n")
        got = parse_hackertarget(raw)
        self.assertEqual(got, ["api.example.com", "www.xycovo.com", "xycovo.com"])

    def test_parse_empty(self):
        from modules.reverse_ip import parse_hackertarget
        self.assertEqual(parse_hackertarget(""), [])
        self.assertEqual(parse_hackertarget("error check your search parameter"), [])


class TestICPParse(unittest.TestCase):
    def test_filed(self):
        from modules.icp import parse_icp
        r = parse_icp('{"code":200,"td":"1-1","type":"企业","icp":"粤B2-20090059-5",'
                      '"unit":"深圳市腾讯计算机系统有限公司","domain":"qq.com","time":"2026-01-15"}')
        self.assertTrue(r["filed"])
        self.assertEqual(r["icp"], "粤B2-20090059-5")
        self.assertEqual(r["unit"], "深圳市腾讯计算机系统有限公司")

    def test_not_filed(self):
        from modules.icp import parse_icp
        r = parse_icp('{"code":400,"msg":"查询失败或没有备案。"}')
        self.assertFalse(r["filed"])
        self.assertIn("没有备案", r["msg"])

    def test_ratelimit_disguised_as_200(self):
        """回归：apihz 限频会返回 code=200 但字段值全是「查询失败」，不能当成备案号。"""
        from modules.icp import parse_icp
        r = parse_icp('{"code":200,"icp":"查询失败","unit":"查询失败","domain":"查询失败","time":"查询失败"}')
        self.assertFalse(r["filed"])
        self.assertIn("限频", r["msg"])

    def test_bad_payload(self):
        from modules.icp import parse_icp
        self.assertFalse(parse_icp("<html>502</html>")["filed"])
        self.assertFalse(parse_icp(None)["filed"])


class TestApiClassify(unittest.TestCase):
    def test_swagger_hit(self):
        from modules.api_unauth import classify
        r = classify("/v3/api-docs", 200, '{"openapi":"3.0.1","paths":{}}', "application/json", 30,
                     ['"openapi"', '"paths"'])
        self.assertTrue(r["hit"])

    def test_html_200_is_not_hit(self):
        from modules.api_unauth import classify
        r = classify("/v3/api-docs", 200, "<html><body>首页</body></html>", "text/html", 30,
                     ['"openapi"', '"paths"'])
        self.assertFalse(r["hit"])

    def test_404_not_hit(self):
        from modules.api_unauth import classify
        self.assertFalse(classify("/actuator", 404, "", "", 0, ['"_links"'])["hit"])

    def test_heapdump_by_content(self):
        from modules.api_unauth import classify
        r = classify("/actuator/heapdump", 200, "x" * 5000, "application/octet-stream", 5000, [])
        self.assertTrue(r["hit"])

    def test_endpoints_table_sane(self):
        from modules.api_unauth import ENDPOINTS
        names = [e[1] for e in ENDPOINTS]
        self.assertGreaterEqual(len(ENDPOINTS), 20)
        self.assertIn("Spring Boot Actuator", names)
        for path, name, expect, risk in ENDPOINTS:
            self.assertTrue(path.startswith("/"))
            self.assertIn(risk, ("高", "中", "低"))


class TestFingerprintRules(unittest.TestCase):
    def test_no_natural_language_thinkphp(self):
        """回归：正文里出现 'think ... php' 不能再被判定为 ThinkPHP（静态博客误报事件）。"""
        import re
        from modules.fingerprint import RULES
        body = "我在文章里聊了 think 和 php 的关系，也提到过 thinkphp 这个框架名字。"
        hits = [r["name"] for r in RULES if r["where"] == "body" and re.search(r["pattern"], body.lower())]
        self.assertNotIn("ThinkPHP", hits)

    def test_techphp_tech_marker_still_hits(self):
        import re
        from modules.fingerprint import RULES
        body = "think_exception: 无法加载模块  ThinkPHP 5.1.37"
        hits = [r["name"] for r in RULES if r["where"] == "body" and re.search(r["pattern"], body.lower())]
        self.assertIn("ThinkPHP", hits)


if __name__ == "__main__":
    unittest.main()
