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


def _from_certspotter(domain: str) -> list:
    """备用证书日志源（crt.sh 挂掉时兜底）：certspotter 公开 API，无需 key。"""
    url = ("https://api.certspotter.com/v1/issuances?domain=%s"
           "&include_subdomains=true&expand=dns_names" % domain)
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    subs = set()
    for row in data if isinstance(data, list) else []:
        for name in row.get("dns_names", []):
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
            print("[*] 未设置 ONEFORALL_HOME，降级使用证书日志查询")
        src = "crt.sh"
        try:
            subs = _from_crtsh(domain)
        except Exception as e:
            print(f"[!] crt.sh 异常: {e}")
            subs = []
        if not subs:
            print("[*] 尝试备用证书源 certspotter")
            try:
                subs = _from_certspotter(domain)
                src = "certspotter"
            except Exception as e:
                print(f"[!] certspotter 也不可用: {e}")
                subs = []
    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs) + ("\n" if subs else ""))
    print(f"[+] 子域枚举完成（{src}，{len(subs)} 个）-> {result_path}")
    return subs


# ── 存活验证（审计补充：证书日志里常有大量历史/失效域名，必须验证后才能入报告）──

def dns_lookup(host: str, timeout: float = 3.0) -> list:
    """解析域名 → 去重排序的 IP 列表；失败返回空列表。

    注意：socket.getaddrinfo 没有 per-call 超时，只能借用进程级默认超时，
    这里保存/恢复原值，避免污染调用方（自审发现）。
    """
    import socket
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    ips = set()
    try:
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(old)
    return sorted(ips)


def http_probe(host: str, timeout: float = 5.0, port: int = None) -> dict:
    """对单个主机做一次轻量 HTTP 探测（先 https 后 http），返回状态/服务头/标题。"""
    import re
    try:
        from . import netutil
    except ImportError:
        import netutil
    suffix = f":{port}" if port else ""
    for scheme in ("https", "http"):
        r = netutil.fetch(f"{scheme}://{host}{suffix}", timeout=timeout, follow=True)
        if r.get("ok") and r.get("status"):
            title = ""
            m = re.search(r"<title[^>]*>([^<]{0,80})", r.get("body", ""), re.I)
            if m:
                title = m.group(1).strip()
            return {"scheme": scheme, "status": r["status"], "server": r.get("headers", {}).get("server", ""),
                    "ctype": r.get("ctype", ""), "title": title, "final_url": r.get("final_url")}
    return {}


def verify_subs(subs: list, workers: int = 8, do_http: bool = True, http_cap: int = 120) -> list:
    """并发（低频）验证子域：先 DNS 解析，能解析的再做一次 HTTP 探活。

    返回 [{host, ips, alive(bool), http:{...}}]；alive 仅当 DNS 可解析。
    """
    import concurrent.futures
    out = []
    if not subs:
        return out
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        dns_map = dict(zip(subs, ex.map(dns_lookup, subs)))
    resolved = [h for h in subs if dns_map.get(h)]
    http_map = {}
    if do_http and resolved:
        targets = resolved[:http_cap]
        if len(resolved) > http_cap:
            print(f"[!] 可解析主机 {len(resolved)} 个，HTTP 探活只做前 {http_cap} 个（避免压力）")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            http_map = dict(zip(targets, ex.map(http_probe, targets)))
    for h in subs:
        ips = dns_map.get(h) or []
        row = {"host": h, "ips": ips, "alive": bool(ips), "http": http_map.get(h, {})}
        out.append(row)
    return out


def run_verify(out: str, workers: int = 8, do_http: bool = True) -> list:
    """读取 out/subdomains.txt，验证存活，写 subdomains_live.json + subdomains_live.txt。"""
    import json as _json
    src = os.path.join(out, "subdomains.txt")
    if not os.path.isfile(src):
        print(f"[!] 找不到 {src}，请先跑子域枚举")
        return []
    with open(src, encoding="utf-8") as f:                # with 管理句柄（自审发现漏了）
        subs = [l.strip() for l in f if l.strip()]
    print(f"[*] 存活验证：{len(subs)} 个子域（DNS 解析 + HTTP 探活，并发 {workers}，低频克制）")
    rows = verify_subs(subs, workers=workers, do_http=do_http)
    live = [r for r in rows if r["alive"]]
    web = [r for r in live if r["http"].get("status")]
    _json.dump(rows, open(os.path.join(out, "subdomains_live.json"), "w", encoding="utf-8"),
               ensure_ascii=False, indent=2)
    with open(os.path.join(out, "subdomains_live.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(r["host"] for r in live) + ("\n" if live else ""))
    print(f"[+] 存活验证完成：可解析 {len(live)} 个（其中 {len(web)} 个有 HTTP 响应）-> subdomains_live.txt / .json")
    for r in live[:20]:
        h = r["http"]
        info = f"{h.get('scheme')}://{h.get('status')} {h.get('title', '')[:28]}" if h else "（无 HTTP 响应）"
        print(f"      {r['host']:<44} {','.join(r['ips'][:2]):<20} {info}")
    if len(live) > 20:
        print(f"      ... 另 {len(live) - 20} 个见 subdomains_live.json")
    return rows

