# -*- coding: utf-8 -*-
"""YAML 化 POC 模板引擎（nuclei 风格子集）。

模板结构:
  id: example-detect
  info:
    name: Example HTTP Detect
    severity: info
  requests:
    - method: GET
      path: "/admin"
      headers: {}
      matchers:
        - type: status          # 状态码匹配
          status: [200, 401, 403]
        - type: contains        # 响应体关键字匹配
          words: ["login"]
      condition: or             # 多 matcher 关系，默认 or
"""
import json

try:
    from . import netutil
except ImportError:
    import netutil

_UA = {"User-Agent": "src-recon-tool/1.0 (+authorized-testing-only)"}


def _match_one(matcher: dict, status: int, body: str) -> bool:
    mtype = matcher.get("type")
    if mtype == "status":
        return status in matcher.get("status", [])
    if mtype == "contains":
        return any(kw.lower() in body.lower() for kw in matcher.get("words", []))
    return False


def _match(matchers: list, status: int, body: str, condition: str = "or") -> bool:
    if not matchers:
        return False
    results = [_match_one(m, status, body) for m in matchers]
    return all(results) if condition == "and" else any(results)


def run_poc(target: str, poc_file: str):
    import yaml
    with open(poc_file, "r", encoding="utf-8") as f:
        tpl = yaml.safe_load(f)
    info = tpl.get("info", {})
    print(f"[*] 执行 POC: {tpl.get('id')} ({info.get('name', '')}, severity={info.get('severity', 'info')})")
    hit_any = False
    for req in tpl.get("requests", []):
        url = target.rstrip("/") + req.get("path", "/")
        method = req.get("method", "GET").upper()
        headers = {**_UA, **req.get("headers", {})}
        data = req.get("body")
        # 统一走 netutil.fetch：协议白名单内建，状态码经 HTTPError 分支也能拿到
        r = netutil.fetch(url, timeout=10, method=method, headers=headers,
                          data=data.encode() if isinstance(data, str) else None)
        status, body = r.get("status"), r.get("body", "")
        if status is None:
            print(f"[!] 请求异常 {url}: {r.get('error')}")
            continue
        if _match(req.get("matchers", []), status, body, req.get("condition", "or")):
            hit_any = True
            print(f"[+] 命中! {url} (HTTP {status})")
            print(json.dumps({"poc": tpl.get("id"), "url": url, "status": status},
                             ensure_ascii=False))
        else:
            print(f"[-] 未命中 {url} (HTTP {status})")
    return hit_any
