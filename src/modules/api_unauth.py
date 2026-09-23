# -*- coding: utf-8 -*-
"""API 文档暴露与未授权访问探测（含软 404 基线 + 存活复验）。

判定流水线（每一步都可能把"假阳性"刷掉）:
  1) 状态码 200
  2) 命中该端点的**技术特征**（≥1 个，多特征端点需 ≥2 个）
  3) 与站点基线比对：软 404 / 全局 403 / 统一跳转 → 一律不算命中
  4) 连续 2 次复验形态一致 → 记 live=True（这才是"存活"）
命中仅代表疑似，报告必须人工复核后再定级（反幻觉纪律）。

输出 api_unauth.json。
"""
import json
import os

try:                                  # 作为包导入时（tests / recon.py）用相对导入
    from . import netutil
except ImportError:                   # 直接执行本文件时的兜底
    import netutil

# (路径, 名称, 命中特征[小写], 风险)
ENDPOINTS = [
    ("/swagger-ui.html",            "Swagger UI",              ["swagger-ui"], "中"),
    ("/swagger-ui/index.html",      "Swagger UI",              ["swagger-ui"], "中"),
    ("/swagger-resources",          "Swagger 资源列表",         ["swagger"], "中"),
    ("/v2/api-docs",                "Swagger API-Docs (v2)",   ['"swagger"', '"paths"'], "中"),
    ("/v3/api-docs",                "OpenAPI 3 文档",          ['"openapi"', '"paths"'], "中"),
    ("/openapi.json",               "OpenAPI 描述文件",         ['"openapi"'], "中"),
    ("/api-docs",                   "API 文档",                ['"swagger"', '"openapi"'], "中"),
    ("/redoc",                      "ReDoc 文档",              ["redoc"], "低"),
    ("/actuator",                   "Spring Boot Actuator",    ['"_links"', '"href"'], "中"),
    ("/actuator/env",               "Actuator env（含配置/口令）", ['"propertysources"'], "高"),
    ("/actuator/health",            "Actuator health",         ['"status"'], "低"),
    ("/actuator/mappings",          "Actuator mappings（全路由）", ['"mappings"'], "中"),
    ("/actuator/beans",             "Actuator beans",          ['"beans"'], "中"),
    ("/actuator/heapdump",          "Heapdump（可提取凭据）",    ["java profile"], "高"),
    ("/druid/index.html",           "Druid 监控台",             ["druid"], "中"),
    ("/druid/websession.json",      "Druid 会话（含登录态）",    ['"result"'], "高"),
    ("/druid/sql.json",             "Druid SQL 监控",           ['"result"'], "中"),
    ("/graphql",                    "GraphQL 端点",            ['"errors"', '"data"'], "中"),
    ("/graphiql",                   "GraphiQL 交互台",          ["graphiql"], "中"),
    ("/eureka/apps",                "Eureka 注册中心",          ["<applications"], "中"),
    ("/nacos/",                     "Nacos 控制台",             ["nacos"], "中"),
    ("/nacos/v1/auth/users",        "Nacos 用户接口（CVE-2021-29441）", ["username", '"pageitems"'], "高"),
    ("/v1/agent/members",           "Consul 成员列表",          ['"member"'], "中"),
    ("/h2-console",                 "H2 数据库控制台",          ["h2-console"], "中"),
    ("/debug/pprof/",               "Go pprof 调试面",          ["pprof"], "中"),
    ("/metrics",                    "Prometheus 指标",          ["# help"], "低"),
    ("/api/v1/users",               "常见 API：用户列表",        ['"username"', '"email"'], "中"),
]


def classify(path: str, status: int, body: str, ctype: str, size: int, expect: list) -> dict:
    """只看内容特征（基线比对与存活复验在外面做）。"""
    if status != 200:
        return {"hit": False}
    low = (body or "").lower()
    if expect:
        matched = [k for k in expect if k in low]
        need = 2 if len(expect) >= 2 else 1
        if len(matched) < need:
            return {"hit": False}
        return {"hit": True, "marker": matched[0], "evidence": "body 含 " + ", ".join(matched[:3])}
    return {"hit": False}


def probe(base_url: str, timeout: int = 12, verify: bool = True) -> tuple:
    base = base_url.rstrip("/")
    bl = netutil.baseline(base, timeout)
    print(f"[*] 站点基线: {bl.get('kind')}（随机路径 → {bl.get('status')}, {bl.get('size')}B, {bl.get('ctype') or '-'}）")
    if bl.get("kind") in ("soft404", "uniform403", "redirect"):
        print(f"[!] 该站存在 catch-all（{bl['kind']}），已启用形态比对过滤——假阳性会被剔除")
    rows, hits = [], []
    for path, name, expect, risk in ENDPOINTS:
        url = base + path
        r = netutil.fetch(url, timeout=timeout)
        verdict = classify(path, r.get("status"), r.get("body", ""), r.get("ctype", ""), r.get("size", 0),
                           [k.lower() for k in expect])
        row = {"path": path, "name": name, "risk": risk, "status": r.get("status"),
               "size": r.get("size", 0), "sha1": r.get("sha1", ""), "ctype": r.get("ctype", ""),
               "final_url": r.get("final_url"), "error": r.get("error"), **verdict}
        if verdict.get("hit"):
            if netutil.is_baseline(r, bl):
                row.update(hit=False, soft404=True,
                           evidence=(row.get("evidence") or "") + " / 与站点基线形态一致（catch-all）")
            else:
                if verify:
                    v = netutil.verify_live(url, tries=2, timeout=timeout, expect_body=verdict.get("marker"))
                    row["live"] = v["live"]
                    row["recheck"] = v
                row["redirected"] = bool(r.get("final_url") and r["final_url"] != url)
                hits.append(row)
                flag = "存活✓" if row.get("live") else "复验未通过✗"
                print(f"[!] {risk}危  命中 {name:<34} {path}  ({row.get('evidence')}) → {flag}")
        rows.append(row)
    order = {"高": 0, "中": 1, "低": 2}
    hits.sort(key=lambda x: (not x.get("live"), order.get(x.get("risk"), 3)))
    return rows, hits


def run_api(url: str, out: str) -> list:
    print(f"[*] API 文档/未授权探测: {url}（{len(ENDPOINTS)} 个候选端点）")
    rows, hits = probe(url)
    live = [h for h in hits if h.get("live")]
    soft = [r for r in rows if r.get("soft404")]
    path = os.path.join(out, "api_unauth.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"base": url, "probed": len(rows), "hits": hits, "live_hits": len(live),
                   "soft404_filtered": len(soft), "all": rows}, f, ensure_ascii=False, indent=2)
    if hits:
        print(f"[+] 探测完成：{len(hits)} 个疑似命中，其中**存活复验通过 {len(live)} 个**"
              f"（catch-all 过滤掉 {len(soft)} 条）")
        for r in hits[:15]:
            print(f"      [{'存活' if r.get('live') else '未复验通过'}][{r['risk']}] {r['name']}  {r['path']}")
    else:
        print(f"[*] 探测完成：未发现暴露的 API 文档/运维端点"
              f"（catch-all 过滤掉 {len(soft)} 条疑似）")
    print(f"    -> {path}")
    return hits


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from modules import api_unauth as m
    m.run_api(sys.argv[1], "out")
