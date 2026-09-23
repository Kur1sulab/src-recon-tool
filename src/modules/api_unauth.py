# -*- coding: utf-8 -*-
"""API 文档暴露与未授权访问探测。

思路：对目标逐个请求「常见的 API 文档 / 运维端点」，
命中后按响应特征判定是「真实暴露」还是「登录页/蜜罐/自定义 404」，
并给出风险级别。命中仅代表疑似，报告里必须人工复核后再定级（反幻觉）。

输出 api_unauth.json（结构化）+ 控制台摘要。
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}

# (路径, 名称, 命中特征[body 小写后出现即算命中], 风险)
ENDPOINTS = [
    ("/swagger-ui.html",            "Swagger UI",              ["swagger-ui", "swagger_ui"], "中"),
    ("/swagger-ui/index.html",      "Swagger UI",              ["swagger-ui"], "中"),
    ("/swagger-resources",          "Swagger 资源列表",         ["swagger", "name"], "中"),
    ("/v2/api-docs",                "Swagger API-Docs (v2)",   ['"swagger"', '"paths"'], "中"),
    ("/v3/api-docs",                "OpenAPI 3 文档",          ['"openapi"', '"paths"'], "中"),
    ("/openapi.json",               "OpenAPI 描述文件",         ['"openapi"'], "中"),
    ("/api-docs",                   "API 文档",                ['"swagger"', '"openapi"'], "中"),
    ("/redoc",                      "ReDoc 文档",              ["redoc"], "低"),
    ("/actuator",                   "Spring Boot Actuator",    ['"_links"'], "中"),
    ("/actuator/env",               "Actuator env（含配置/口令）", ['"propertysources"', '"activeprofiles"'], "高"),
    ("/actuator/health",            "Actuator health",         ['"status"'], "低"),
    ("/actuator/mappings",          "Actuator mappings（全路由）", ['"contexts"', '"mappings"'], "中"),
    ("/actuator/beans",             "Actuator beans",          ['"beans"'], "中"),
    ("/actuator/heapdump",          "Heapdump（可提取凭据）",    [], "高"),
    ("/druid/index.html",           "Druid 监控台",             ["druid"], "中"),
    ("/druid/websession.json",      "Druid 会话（含登录态）",    ['"result"', '"content"'], "高"),
    ("/druid/sql.json",             "Druid SQL 监控",           ['"result"'], "中"),
    ("/graphql",                    "GraphQL 端点",            ['"errors"', '"data"', "graphql"], "中"),
    ("/graphiql",                   "GraphiQL 交互台",          ["graphiql"], "中"),
    ("/eureka/apps",                "Eureka 注册中心",          ["<applications", "instances"], "中"),
    ("/nacos/",                     "Nacos 控制台",             ["nacos"], "中"),
    ("/nacos/v1/auth/users",        "Nacos 用户接口（CVE-2021-29441）", ["username", '"pageitems"'], "高"),
    ("/v1/agent/members",           "Consul 成员列表",          ['"member"', '"name"'], "中"),
    ("/h2-console",                 "H2 数据库控制台",          ["h2-console", "login.jsp"], "中"),
    ("/debug/pprof/",               "Go pprof 调试面",          ["pprof"], "中"),
    ("/metrics",                    "Prometheus 指标",          ["# help", "prometheus"], "低"),
    ("/api/v1/users",               "常见 API：用户列表",        ['"id"', '"username"'], "中"),
]

_CONNECT_TIMEOUT = 12


def classify(path: str, status: int, body: str, ctype: str, expect_ms: int, expect: list) -> dict:
    """判定一条探测结果。返回 {hit, risk, evidence} ；未命中返回 {'hit': False}。"""
    if status != 200:
        return {"hit": False}
    low = (body or "").lower()
    if "text/html" in ctype and expect and not any(k in low for k in expect):
        return {"hit": False}                      # 200 但是普通页面（多半是自定义首页/404 跳转）
    if expect:
        matched = [k for k in expect if k in low]
        if not matched:
            return {"hit": False}
        return {"hit": True, "evidence": "body 含 " + ", ".join(matched[:3])}
    # 无特征关键词的端点（如 heapdump）：靠内容类型 + 体积判定
    if "octet-stream" in ctype or (len(body) > 2000 and "html" not in ctype):
        return {"hit": True, "evidence": f"响应 {len(body)}B，类型 {ctype or '未知'}，无 HTML 特征（疑似二进制转储）"}
    return {"hit": False}


def probe(base_url: str, timeout: int = _CONNECT_TIMEOUT) -> list:
    base = base_url.rstrip("/")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    results = []
    for path, name, expect, risk in ENDPOINTS:
        url = base + path
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                raw = r.read(200000)
                body = raw.decode("utf-8", "ignore")
                ctype = r.headers.get("Content-Type", "")
                status = r.status
        except urllib.error.HTTPError as e:
            status, body, ctype = e.code, "", ""
        except Exception as e:
            results.append({"path": path, "name": name, "status": None, "error": str(e)[:80], "hit": False})
            continue
        verdict = classify(path, status, body, ctype, len(body), [k.lower() for k in expect])
        row = {"path": path, "name": name, "risk": risk, "status": status, "size": len(body),
               **verdict}
        results.append(row)
        if verdict.get("hit"):
            print(f"[!] {risk}危  命中 {name:<34} {path}  ({verdict.get('evidence')})")
    return results


def run_api(url: str, out: str) -> list:
    print(f"[*] API 文档/未授权探测: {url}（{len(ENDPOINTS)} 个候选端点）")
    rows = probe(url)
    hits = [r for r in rows if r.get("hit")]
    path = os.path.join(out, "api_unauth.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"base": url, "probed": len(rows), "hits": hits, "all": rows}, f,
                  ensure_ascii=False, indent=2)
    order = {"高": 0, "中": 1, "低": 2}
    hits.sort(key=lambda r: order.get(r.get("risk"), 3))
    if hits:
        print(f"[+] 探测完成：{len(hits)} 个疑似命中（务必人工复核后再写报告）")
        for r in hits[:15]:
            print(f"      [{r['risk']}] {r['name']}  {r['path']}")
    else:
        print("[*] 探测完成：未发现暴露的 API 文档/运维端点")
    print(f"    -> {path}")
    return hits


if __name__ == "__main__":
    import sys
    run_api(sys.argv[1], "out")
