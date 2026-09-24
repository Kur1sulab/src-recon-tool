# -*- coding: utf-8 -*-
"""IP 反查域名：输入 IP，输出该 IP 上托管过的域名（用于资产测绘）。

数据源：hackertarget reverseiplookup（免 key、纯文本，2026-09 实测稳定）。
其他常见源（webscan.cc / rapiddns / ip138）已实测失效或需过盾，故不内置；
如需扩展，在 SOURCES 里加 (名称, 解析函数) 即可。
输出 reverse_domains.txt。
"""
import re
import time

try:
    from . import netutil
except ImportError:
    import netutil

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
        r = netutil.fetch(url, timeout=25)
        if r.get("ok") and r.get("status") == 200 and r.get("body"):
            return r["body"]
        last = r.get("error") or f"HTTP {r.get('status')}"
        print(f"[!] 反查第 {i}/{tries} 次失败: {last}")
        if i < tries:
            time.sleep(2 * i)
    print(f"[!] 反查请求全部失败: {last}")
    return ""


def reverse_ip(ip: str) -> list:
    """返回该 IP 关联的域名列表（去重排序）。"""
    return parse_hackertarget(_fetch(f"https://api.hackertarget.com/reverseiplookup/?q={ip}"))


def run_reverse(ip: str, out: str) -> list:
    print(f"[*] IP 反查域名: {ip}")
    doms = reverse_ip(ip)
    path = netutil.safe_write(out, "reverse_domains.txt",
                              "\n".join(doms) + ("\n" if doms else ""))
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
