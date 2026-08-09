# -*- coding: utf-8 -*-
"""敏感路径探测：内置常见路径字典，按状态码判断存活。
仅做少量请求（字典可控），避免对目标造成压力。
"""
import json
import os
import ssl
import urllib.error
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}

PATHS = [
    "/robots.txt", "/.git/config", "/.env", "/admin", "/admin/login",
    "/api/swagger", "/swagger-ui.html", "/v2/api-docs",
    "/wp-login.php", "/.svn/entries", "/.DS_Store",
    "/phpinfo.php", "/server-status", "/actuator", "/actuator/env",
    "/druid/index.html", "/backup.zip", "/www.zip", "/config.php.bak",
]


def run_paths(url: str, out: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    found = []
    base = url.rstrip("/")
    for p in PATHS:
        try:
            req = urllib.request.Request(base + p, headers=_UA)
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception:
            continue
        if status in (200, 301, 302, 401, 403):
            found.append({"path": p, "status": status})
    path = os.path.join(out, "paths.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(found, f, ensure_ascii=False, indent=2)
    print(f"[+] 敏感路径探测完成（{len(found)} 个存活）-> {path}")
