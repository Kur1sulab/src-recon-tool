# -*- coding: utf-8 -*-
"""子域枚举：优先调用 OneForAll（ONEFORALL_HOME 环境变量指定路径），
无 OneForAll 时降级为 crt.sh 证书透明度日志查询（纯标准库，无需 key）。
输出去重排序后的 subdomains.txt。
"""
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request

_UA = {"User-Agent": "src-recon-tool/1.0 (+authorized-testing-only)"}


def _from_oneforall(domain: str, out: str) -> list:
    home = os.environ.get("ONEFORALL_HOME", "")
    if not home:
        return []
    exe = os.path.join(home, "oneforall.py")
    if not os.path.isfile(exe):
        print(f"[!] ONEFORALL_HOME 已设置但找不到 {exe}")
        return []
    subprocess.run([sys.executable, exe, "--target", domain, "--fmt", "json", "--path", out],
                   check=False, timeout=1800)
    # OneForAll 输出 <out>/<domain>.json，逐行 {"subdomain": ...}
    result = os.path.join(out, f"{domain}.json")
    subs = set()
    if os.path.isfile(result):
        with open(result, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().strip(",")
                if not line:
                    continue
                try:
                    subs.add(json.loads(line).get("subdomain", "").strip("."))
                except json.JSONDecodeError:
                    continue
    return sorted(s for s in subs if s)


def _from_crtsh(domain: str, tries: int = 3) -> list:
    """crt.sh 偶发 502/超时，做 3 次退避重试；彻底失败时优雅返回空列表而非抛栈。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = None
    for i in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                data = json.load(r)
            break
        except Exception as e:
            print(f"[!] crt.sh 第 {i}/{tries} 次请求失败: {e}")
            if i < tries:
                time.sleep(2 * i)
    if data is None:
        print("[!] crt.sh 不可用（重试均失败）。可设置 ONEFORALL_HOME 走 OneForAll，或稍后重试")
        return []
    subs = set()
    for row in data:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain.lower()):
                subs.add(name)
    return sorted(subs)


def run_subdomain(domain: str, out: str):
    result_path = os.path.join(out, "subdomains.txt")
    subs = _from_oneforall(domain, out)
    if subs:
        src = "OneForAll"
    else:
        if not os.environ.get("ONEFORALL_HOME"):
            print("[*] 未设置 ONEFORALL_HOME，降级使用 crt.sh 证书日志查询")
        subs = _from_crtsh(domain)
        src = "crt.sh"
    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs) + ("\n" if subs else ""))
    print(f"[+] 子域枚举完成（{src}，{len(subs)} 个）-> {result_path}")
