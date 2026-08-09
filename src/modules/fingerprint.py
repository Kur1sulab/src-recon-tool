# -*- coding: utf-8 -*-
"""指纹识别：内置常用 Web 指纹规则（headers + body 双通道），
输出命中的 CMS/框架/中间件。规则可按 EHole 思路自行扩充。
"""
import json
import os
import re
import ssl
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}

RULES = [
    {"name": "ThinkPHP",  "where": "body",   "pattern": r"thinkphp|think\s*php", "type": "framework"},
    {"name": "Shiro",     "where": "header", "pattern": r"rememberme=deleteme",  "type": "framework"},
    {"name": "Spring",    "where": "body",   "pattern": r"whitelabel error page", "type": "framework"},
    {"name": "WordPress", "where": "body",   "pattern": r"wp-content|wp-includes", "type": "cms"},
    {"name": "Discuz",    "where": "body",   "pattern": r"discuz!|forum\.php\?mod=", "type": "cms"},
    {"name": "Nginx",     "where": "header", "pattern": r"nginx",                "type": "server"},
    {"name": "Apache",    "where": "header", "pattern": r"apache",               "type": "server"},
    {"name": "IIS",       "where": "header", "pattern": r"microsoft-iis",        "type": "server"},
    {"name": "Vue",       "where": "body",   "pattern": r"data-v-[0-9a-f]{8}|__vue__", "type": "frontend"},
    {"name": "React",     "where": "body",   "pattern": r"data-reactroot|__react", "type": "frontend"},
]


def run_fingerprint(url: str, out: str):
    hits = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            body = r.read(300000).decode("utf-8", "ignore").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
    except Exception as e:
        print(f"[!] 指纹识别请求失败: {e}")
        body = headers = ""
    for rule in RULES:
        haystack = headers if rule["where"] == "header" else body
        if re.search(rule["pattern"], haystack):
            hits.append({"name": rule["name"], "type": rule["type"]})
    path = os.path.join(out, "fingerprint.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=2)
    names = "、".join(h["name"] for h in hits) or "无"
    print(f"[+] 指纹识别完成（{len(hits)} 个命中: {names}）-> {path}")
