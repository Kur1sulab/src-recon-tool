# -*- coding: utf-8 -*-
"""第三轮：资产档案 + 证据包模块的测试与自审。

审计关注点：
  1) report.md 不得内联敏感值（口令/会话/密钥），只能出现端点、状态码、大小、证据目录
  2) zip 归档名必须相对化（不得出现绝对路径或 ..）
  3) 产出缺失/为空的目录上不能崩（侦察中途中断是常态）
  4) 幂等：重复生成覆盖自身，不追加
"""
import json
import os
import sys
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from modules import report as report_mod   # noqa: E402

OUT = os.path.join(ROOT, "out", "_unittest3")


def _quiet(fn, *a, **kw):
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        return fn(*a, **kw)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.out = os.path.join(OUT, self._testMethodName)
        os.makedirs(self.out, exist_ok=True)
        # 合成一份"侦察产出"（含真实字段名，值用占位）
        with open(os.path.join(self.out, "reverse_domains.txt"), "w", encoding="utf-8") as f:
            f.write("example.com\n")
        with open(os.path.join(self.out, "subdomains.txt"), "w", encoding="utf-8") as f:
            f.write("a.example.com\nb.example.com\n")
        json.dump([{"host": "a.example.com", "ips": ["1.2.3.4"], "alive": True,
                    "http": {"scheme": "https", "status": 200, "title": "T"}},
                   {"host": "b.example.com", "ips": [], "alive": False, "http": {}}],
                  open(os.path.join(self.out, "subdomains_live.json"), "w", encoding="utf-8"))
        json.dump({"domain": "example.com", "filed": True, "icp": "京ICP备00000000号-1",
                   "unit": "示例科技有限公司", "type": "企业", "time": "2026-01-01"},
                  open(os.path.join(self.out, "icp_example.com.json"), "w", encoding="utf-8"))
        json.dump([{"name": "Swagger UI", "type": "api"}], open(os.path.join(self.out, "fingerprint.json"), "w", encoding="utf-8"))
        json.dump({"base": "https://example.com", "baseline": {"kind": "soft404"},
                   "alive": [{"path": "/.env", "status": 200, "size": 63, "verified": True}], "notes": []},
                  open(os.path.join(self.out, "paths.json"), "w", encoding="utf-8"))
        json.dump({"base": "https://example.com", "probed": 27, "live_hits": 1, "soft404_filtered": 3,
                   "hits": [{"path": "/actuator/env", "name": "Actuator env（含配置/口令）", "risk": "高",
                             "live": True, "evidence_dir": os.path.join(self.out, "evidence", "example.com", "actuator_env"),
                             "evidence": "body 含 \"propertysources\""}]},
                  open(os.path.join(self.out, "api_unauth.json"), "w", encoding="utf-8"))
        ev = os.path.join(self.out, "evidence", "example.com", "actuator_env")
        os.makedirs(ev, exist_ok=True)
        with open(os.path.join(ev, "meta.json"), "w", encoding="utf-8") as f:
            json.dump({"url": "https://example.com/actuator/env", "live": True}, f)
        with open(os.path.join(ev, "response.snippet.txt"), "w", encoding="utf-8") as f:
            f.write('{"spring.datasource.password":"SUPER_SECRET_VALUE"}')     # 敏感值只应存在于证据文件里
        with open(os.path.join(ev, "repro.md"), "w", encoding="utf-8") as f:
            f.write("curl -sk -i 'https://example.com/actuator/env'\n")

    def test_missing_outputs_do_not_crash(self):
        empty = os.path.join(OUT, "emptycase")
        os.makedirs(empty, exist_ok=True)
        b = report_mod.collect(empty, "nothing.example")
        md = report_mod.render_md(b)
        self.assertIn("目标资产档案", md)
        self.assertIn("待人工跟进", md)

    def test_report_does_not_inline_secrets(self):
        path = _quiet(report_mod.run_report, self.out, "example.com")
        md = open(path, encoding="utf-8").read()
        self.assertNotIn("SUPER_SECRET_VALUE", md, "report.md 内联了敏感值")
        self.assertIn("/actuator/env", md)
        self.assertIn("京ICP备00000000号-1", md)
        self.assertIn("存活 ✓", md)

    def test_evidence_zip_arcnames_are_relative(self):
        zp = report_mod.pack_evidence(self.out, "example.com")
        self.assertTrue(zp and zp.endswith(".zip"))
        with zipfile.ZipFile(zp) as z:
            names = z.namelist()
        self.assertTrue(any("repro.md" in n for n in names))
        for n in names:
            self.assertFalse(n.startswith("/") or n.startswith("\\\\"), f"绝对路径: {n}")
            self.assertNotIn("..", n, f"疑似穿越: {n}")

    def test_idempotent_regeneration(self):
        p1 = _quiet(report_mod.run_report, self.out, "example.com")
        size1 = os.path.getsize(p1)
        p2 = _quiet(report_mod.run_report, self.out, "example.com")
        size2 = os.path.getsize(p2)
        self.assertEqual(p1, p2)
        self.assertLess(abs(size1 - size2), 400, "重复生成不应持续追加内容")

    def test_poisoned_icp_record_is_not_rendered_as_real(self):
        """审计回归：历史版本把限频写成了 filed=true，渲染层必须挡住这种脏数据。"""
        out = os.path.join(OUT, "poisoned")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "reverse_domains.txt"), "w", encoding="utf-8") as f:
            f.write("bad.example\n")
        with open(os.path.join(out, "icp_bad.example.json"), "w", encoding="utf-8") as f:
            json.dump({"domain": "bad.example", "filed": True, "icp": "查询失败",
                       "unit": "查询失败", "type": "查询失败", "time": "查询失败"}, f)
        md = report_mod.render_md(report_mod.collect(out, "poisoned"))
        self.assertNotIn("查询失败 · 查询失败", md)
        self.assertIn("未查询到有效备案信息", md)

    def test_pack_returns_empty_when_no_evidence(self):
        empty = os.path.join(OUT, "noevidence")
        os.makedirs(empty, exist_ok=True)
        self.assertEqual(report_mod.pack_evidence(empty, "x"), "")


if __name__ == "__main__":
    unittest.main()
