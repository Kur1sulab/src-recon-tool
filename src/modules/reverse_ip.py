# -*- coding: utf-8 -*-
"""IP 反查域名：输入 IP，输出该 IP 上托管过的域名（用于资产测绘）。

数据源：hackertarget reverseiplookup（免 key、纯文本，2026-09 实测稳定）。
其他常见源（webscan.cc / rapiddns / ip138）已实测失效或需过盾，故不内置；
如需扩展，在 SOURCES 里加 (名称, 解析函数) 即可。
输出 reverse_domains.txt。
"""
import re
import ssl
import time
import urllib.request

_UA = {"User-Agent": "src-recon-tool/1.0 (+authorized-testing-only)"}

# 只保留合法域名（过滤 ip6.arpa 之类的反向解析残留）
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$", re.I)
_SKIP_SUFFIX = (".arpa", ".in-addr.arpa", ".ip6.arpa", ".local", ".lan")


def parse_hackertarget(text: str) -> list:
    """解析 hackertarget 的纯文本响应（每行一个域名）。失败时返回空列表。"""
    out = []
    for line in (text or "").splitlines():
        name = line.strip().lower().rstrip(".")
        if not name or " " in name:
            continue
        if name.endswith(_SKIP_SUFFIX):
            continue
        if _DOMAIN_RE.match(name):
            out.append(name)
    return sorted(set(out))


def _fetch(url: str, tries: int = 3) -> str:
    last = None
    for i in range(1, tries + 1):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            last = e
            print(f"[!] 反查第 {i}/{tries} 次失败: {e}")
            if i < tries:
                time.sleep(2 * i)
    print(f"[!] 反查请求全部失败: {last}")
    return ""


def reverse_ip(ip: str) -> list:
    """返回该 IP 关联的域名列表（去重排序）。"""
    return parse_hackertarget(_fetch(f"https://api.hackertarget.com/reverseiplookup/?q={ip}"))


def run_reverse(ip: str, out: str) -> list:
    import os
    print(f"[*] IP 反查域名: {ip}")
    doms = reverse_ip(ip)
    path = os.path.join(out, "reverse_domains.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(doms) + ("\n" if doms else ""))
    if doms:
        print(f"[+] 反查完成，共 {len(doms)} 个域名 -> {path}")
        for d in doms[:20]:
            print(f"      {d}")
        if len(doms) > 20:
            print(f"      ... 另 {len(doms) - 20} 个")
    else:
        print(f"[!] 未反查到域名（可能该 IP 无 PTR 记录，或数据源限流）-> {path}")
    return doms


if __name__ == "__main__":
    import sys
    run_reverse(sys.argv[1], "out")
