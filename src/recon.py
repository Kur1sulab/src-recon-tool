#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SRC 信息收集自动化工具 CLI 入口。

用法（DOMAIN 或 IP 都吃，工具自动识别）:
  python src/recon.py all -t example.com          # 域名全流程
  python src/recon.py all -t 47.100.49.228        # IP 全流程（反查域名→ICP→指纹→API）
  python src/recon.py subdomain -d example.com
  python src/recon.py reverse -i 47.100.49.228    # IP 反查域名
  python src/recon.py icp -d example.com          # ICP 备案查询
  python src/recon.py api -u https://example.com  # API 文档/未授权探测
  python src/recon.py fingerprint -u https://example.com
  python src/recon.py paths -u https://example.com
  python src/recon.py poc -t https://example.com -p pocs/example.yaml
  python src/recon.py llm -d example.com

仅限授权范围内的安全测试使用。
"""
import argparse
import ipaddress
import os
import socket
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def make_outdir(target: str) -> str:
    out = os.path.join("out", target.replace("://", "_").replace("/", "_").replace(":", "_"))
    os.makedirs(out, exist_ok=True)
    return out


def pick_base(host: str) -> str:
    """给主机挑一个能通的 base URL：优先 https，失败退 http。"""
    ctx = None
    import ssl
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "src-recon-tool/1.0"})
            with urllib.request.urlopen(req, timeout=10, context=c) as r:
                if r.status < 500:
                    return url
        except Exception:
            continue
    return f"https://{host}"


def cmd_all(args):
    target = args.target
    out = make_outdir(target)
    from modules.fingerprint import run_fingerprint
    from modules.api_unauth import run_api
    from modules.llm_assist import run_llm

    if is_ip(target):
        # ── IP 分支：反查域名 → 逐个 ICP → 指纹 → API 探测 ──
        from modules.reverse_ip import run_reverse
        from modules.icp import run_icp
        doms = run_reverse(target, out)
        for d in doms[:5]:                      # 备案查询最多查 5 个，避免限频
            try:
                run_icp(d, out)
            except Exception as e:
                print(f"[!] {d} 备案查询失败: {e}")
        # 裸 IP 常被按域名路由的站点返回 404，优先用反查出的域名探测
        host = doms[0] if doms else target
        if doms:
            print(f"[*] 用反查域名 {host} 作为探测入口（裸 IP {target} 直连多为 404/默认页）")
        base = pick_base(host)
        print(f"[*] 目标站点探测 base = {base}")
        run_fingerprint(base, out)
        run_api(base, out)
    else:
        # ── 域名分支：子域 → 存活验证 → 资产 → ICP → 指纹 → 路径 → API → LLM ──
        from modules.subdomain import run_subdomain, run_verify
        from modules.asset import run_asset
        from modules.icp import run_icp
        from modules.paths import run_paths
        run_subdomain(target, out)
        run_verify(out)                       # 审计补充：证书日志含大量失效域名，必须验证存活
        run_asset(target, out)
        try:
            run_icp(target, out)
        except Exception as e:
            print(f"[!] 备案查询失败: {e}")
        base = pick_base(target)
        run_fingerprint(base, out)
        run_paths(base, out)
        run_api(base, out)
    run_llm(out)
    print(f"[+] 全流程完成，输出目录: {out}")


def main():
    p = argparse.ArgumentParser(prog="src-recon-tool", description="SRC 信息收集自动化工具（仅限授权测试）")
    sub = p.add_subparsers(dest="cmd")
    pa = sub.add_parser("all"); pa.add_argument("-t", "--target", "-d", "--domain", dest="target", required=True,
                                                help="域名或 IP，自动识别")
    ps = sub.add_parser("subdomain"); ps.add_argument("-d", "--domain", required=True)
    ps.add_argument("--verify", action="store_true", help="枚举后立即做存活验证（DNS + HTTP）")
    pv = sub.add_parser("verify"); pv.add_argument("-d", "--domain", required=True,
                                                   help="对 out/<domain>/subdomains.txt 做存活验证")
    pv.add_argument("-w", "--workers", type=int, default=8, help="并发数（默认 8，低频克制）")
    pa2 = sub.add_parser("asset"); pa2.add_argument("-d", "--domain", required=True)
    pr = sub.add_parser("reverse"); pr.add_argument("-i", "--ip", required=True)
    pi = sub.add_parser("icp"); pi.add_argument("-d", "--domain", required=True)
    pk = sub.add_parser("api"); pk.add_argument("-u", "--url", required=True)
    pf = sub.add_parser("fingerprint"); pf.add_argument("-u", "--url", required=True)
    pp = sub.add_parser("paths"); pp.add_argument("-u", "--url", required=True)
    pc = sub.add_parser("poc"); pc.add_argument("-t", "--target", required=True); pc.add_argument("-p", "--poc", required=True)
    pl = sub.add_parser("llm"); pl.add_argument("-d", "--domain", required=True)
    args = p.parse_args()

    if args.cmd == "all":
        cmd_all(args)
    elif args.cmd == "subdomain":
        from modules.subdomain import run_subdomain, run_verify
        out = make_outdir(args.domain)
        run_subdomain(args.domain, out)
        if getattr(args, "verify", False):
            run_verify(out)
    elif args.cmd == "verify":
        from modules.subdomain import run_verify
        run_verify(make_outdir(args.domain), workers=getattr(args, "workers", 8))
    elif args.cmd == "asset":
        from modules.asset import run_asset
        run_asset(args.domain, make_outdir(args.domain))
    elif args.cmd == "reverse":
        from modules.reverse_ip import run_reverse
        run_reverse(args.ip, make_outdir(args.ip))
    elif args.cmd == "icp":
        from modules.icp import run_icp
        run_icp(args.domain, make_outdir(args.domain))
    elif args.cmd == "api":
        from modules.api_unauth import run_api
        run_api(args.url, make_outdir(args.url))
    elif args.cmd == "fingerprint":
        from modules.fingerprint import run_fingerprint
        run_fingerprint(args.url, make_outdir(args.url))
    elif args.cmd == "paths":
        from modules.paths import run_paths
        run_paths(args.url, make_outdir(args.url))
    elif args.cmd == "poc":
        from modules.poc_engine import run_poc
        run_poc(args.target, args.poc)
    elif args.cmd == "llm":
        from modules.llm_assist import run_llm
        run_llm(make_outdir(args.domain))
    else:
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
