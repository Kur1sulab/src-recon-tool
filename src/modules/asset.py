# -*- coding: utf-8 -*-
"""资产测绘：FOFA / Hunter API（key 走环境变量，绝不硬编码）。
FOFA:   FOFA_EMAIL + FOFA_KEY
Hunter: HUNTER_KEY
两者都未配置时跳过并提示，不阻断流水线。
"""
import base64
import json
import os
import urllib.parse

try:
    from . import netutil
except ImportError:
    import netutil

_UA = {"User-Agent": "src-recon-tool/1.0 (+authorized-testing-only)"}


def _fofa(domain: str) -> list:
    email = os.environ.get("FOFA_EMAIL", "")
    key = os.environ.get("FOFA_KEY", "")
    if not (email and key):
        return []
    q = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    params = urllib.parse.urlencode({
        "qbase64": q, "email": email, "key": key,
        "size": 100, "fields": "host,ip,port,protocol",
    })
    url = netutil.check_http_url(f"https://fofa.info/api/v1/search/all?{params}")
    r = netutil.fetch(url, timeout=20)
    if not (r.get("ok") and r.get("status") == 200 and r.get("body")):
        print(f"[!] FOFA 请求失败: {r.get('error') or r.get('status')}")
        return []
    data = json.loads(r["body"])
    if data.get("error"):
        print(f"[!] FOFA 返回错误: {data.get('errmsg')}")
        return []
    return [f"{row[0]}|{row[1]}|{row[2]}|{row[3]}" for row in data.get("results", [])]


def _hunter(domain: str) -> list:
    key = os.environ.get("HUNTER_KEY", "")
    if not key:
        return []
    q = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    url = netutil.check_http_url("https://hunter.qianxin.com/openApi/search?"
                                 f"api-key={key}&search={q}&page=1&page_size=100")
    r = netutil.fetch(url, timeout=20)
    if not (r.get("ok") and r.get("status") == 200 and r.get("body")):
        print(f"[!] Hunter 请求失败: {r.get('error') or r.get('status')}")
        return []
    data = json.loads(r["body"])
    if data.get("code") != 200:
        print(f"[!] Hunter 返回错误: {data.get('message')}")
        return []
    return [f"{a.get('domain','')}|{a.get('ip','')}|{a.get('port','')}|{a.get('protocol','')}"
            for a in data.get("data", {}).get("arr", []) or []]


def run_asset(domain: str, out: str):
    items, sources = [], []
    try:
        fofa = _fofa(domain)
        if fofa:
            items += fofa
            sources.append(f"FOFA {len(fofa)} 条")
    except Exception as e:
        print(f"[!] FOFA 查询失败: {e}")
    try:
        hunter = _hunter(domain)
        if hunter:
            items += hunter
            sources.append(f"Hunter {len(hunter)} 条")
    except Exception as e:
        print(f"[!] Hunter 查询失败: {e}")
    if not sources:
        print("[!] 未配置 FOFA_EMAIL/FOFA_KEY 或 HUNTER_KEY，跳过资产测绘")
    path = netutil.safe_write(out, "assets.txt",
                              "".join(it + "\n" for it in dict.fromkeys(items)))
    print(f"[+] 资产测绘完成（{'+'.join(sources) if sources else '0 条'}）-> {path}")
