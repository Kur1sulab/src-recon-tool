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
import ssl
import urllib.error
import urllib.request

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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hit_any = False
    for req in tpl.get("requests", []):
        url = target.rstrip("/") + req.get("path", "/")
        method = req.get("method", "GET").upper()
        headers = {**_UA, **req.get("headers", {})}
        data = req.get("body")
        req_obj = urllib.request.Request(
            url, method=method, headers=headers,
            data=data.encode() if isinstance(data, str) else None)
        try:
            with urllib.request.urlopen(req_obj, timeout=10, context=ctx) as r:
                status, body = r.status, r.read(100000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read(100000).decode("utf-8", "ignore") if e.fp else ""
        except Exception as e:
            print(f"[!] 请求异常 {url}: {e}")
            continue
        if _match(req.get("matchers", []), status, body, req.get("condition", "or")):
            hit_any = True
            print(f"[+] 命中! {url} (HTTP {status})")
            print(json.dumps({"poc": tpl.get("id"), "url": url, "status": status},
                             ensure_ascii=False))
        else:
            print(f"[-] 未命中 {url} (HTTP {status})")
    return hit_any
