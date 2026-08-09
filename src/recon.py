#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SRC 信息收集自动化工具 CLI 入口。

用法:
  python src/recon.py all -d example.com
  python src/recon.py subdomain -d example.com
  python src/recon.py asset -d example.com
  python src/recon.py fingerprint -u https://example.com
  python src/recon.py paths -u https://example.com
  python src/recon.py poc -t https://example.com -p pocs/example.yaml
  python src/recon.py llm -d example.com

仅限授权范围内的安全测试使用。
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def make_outdir(target: str) -> str:
    out = os.path.join("out", target.replace("://", "_").replace("/", "_").replace(":", "_"))
    os.makedirs(out, exist_ok=True)
    return out


def cmd_all(args):
    out = make_outdir(args.domain)
    from modules.subdomain import run_subdomain
    from modules.asset import run_asset
    from modules.fingerprint import run_fingerprint
    from modules.paths import run_paths
    from modules.llm_assist import run_llm
    run_subdomain(args.domain, out)
    run_asset(args.domain, out)
    run_fingerprint(f"https://{args.domain}", out)
    run_paths(f"https://{args.domain}", out)
    run_llm(out)
    print(f"[+] 全流程完成，输出目录: {out}")


def main():
    p = argparse.ArgumentParser(prog="src-recon-tool", description="SRC 信息收集自动化工具（仅限授权测试）")
    sub = p.add_subparsers(dest="cmd")
    pa = sub.add_parser("all"); pa.add_argument("-d", "--domain", required=True)
    ps = sub.add_parser("subdomain"); ps.add_argument("-d", "--domain", required=True)
    pa2 = sub.add_parser("asset"); pa2.add_argument("-d", "--domain", required=True)
    pf = sub.add_parser("fingerprint"); pf.add_argument("-u", "--url", required=True)
    pp = sub.add_parser("paths"); pp.add_argument("-u", "--url", required=True)
    pc = sub.add_parser("poc"); pc.add_argument("-t", "--target", required=True); pc.add_argument("-p", "--poc", required=True)
    pl = sub.add_parser("llm"); pl.add_argument("-d", "--domain", required=True)
    args = p.parse_args()

    if args.cmd == "all":
        cmd_all(args)
    elif args.cmd == "subdomain":
        from modules.subdomain import run_subdomain
        run_subdomain(args.domain, make_outdir(args.domain))
    elif args.cmd == "asset":
        from modules.asset import run_asset
        run_asset(args.domain, make_outdir(args.domain))
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
