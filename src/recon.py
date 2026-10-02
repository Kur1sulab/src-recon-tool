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
  python src/recon.py jsintel -u https://example.com  # JS 情报提取（端点/敏感线索/域名）
  python src/recon.py portscan -t 47.100.49.228   # 常用端口扫描（仅限授权目标）
  python src/recon.py fingerprint -u https://example.com
  python src/recon.py paths -u https://example.com
  python src/recon.py poc -t https://example.com -p pocs/example.yaml

仅限授权范围内的安全测试使用。
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 桌面壳进度事件落盘路径（--progress-file / RECON_PROGRESS_FILE；空=关闭）
_PROGRESS_FILE = ""


def _emit(event, module="", detail=""):
    """追加一条进度事件到 JSONL（UTF-8）；任何落盘失败静默吞掉，绝不影响扫描。"""
    if not _PROGRESS_FILE:
        return
    rec = {"ts": round(time.time(), 3), "event": event, "module": module, "detail": str(detail)}
    try:
        with open(_PROGRESS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _run_step(name, fn, fatal=True):
    """模块级插桩：start/done/fail 事件 + 原调用透传。

    fatal=True 时异常照常上抛（流水线失败）；fatal=False 时降级为警告不阻断主流程。
    """
    _emit("start", name, "")
    try:
        result = fn()
    except Exception as e:
        _emit("fail", name, str(e))
        if fatal:
            raise
        print(f"[!] {name} 失败（不影响主流程）: {e}")
        return None
    _emit("done", name, "")
    return result


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def make_outdir(target: str) -> str:
    """out/<target 清洗>——与 Go 引擎 MakeOutdir（engine-go/internal/cli/cli.go）
    逐字符同规则（fix1 P1 双引擎同步加固）：
      1) :// / / \ : ? & = " < > | * 全部换 _——反斜杠是 Windows 路径分隔符，
         不换则 ..\..\ 直接在 out/ 之外建目录；? & = 等 Windows 非法字符原样
         进目录名会让 makedirs 报 WinError 123，Linux 侧则会把含潜在 api_key 的
         完整 query 持久化进文件系统路径；
      2) 去首尾点号与空格；清洗后为空或 ".."（纯穿越锚）回 "unknown"。
    """
    name = (target.replace("://", "_").replace("/", "_").replace("\\", "_")
            .replace(":", "_").replace("?", "_").replace("&", "_").replace("=", "_")
            .replace('"', "_").replace("<", "_").replace(">", "_").replace("|", "_")
            .replace("*", "_"))
    name = name.strip(". ")
    if name in ("", ".."):
        name = "unknown"
    # fix2 P3（与 Go MakeOutdir/DefuseWindowsReservedStem 同步）：Windows 保留
    # 设备名主干补 _（con/nul/aux/com1-9/lpt1-9，任意扩展名）——实测 `report -t
    # CON` 类目标会建出设备名目录，与文件层 safe_filename 的加固不一致。
    stem, dot, ext = name.partition(".")
    if stem.lower() in {"con", "prn", "aux", "nul",
                        *[f"com{i}" for i in range(1, 10)],
                        *[f"lpt{i}" for i in range(1, 10)]}:
        name = stem + "_" + dot + ext
    out = os.path.join("out", name)
    os.makedirs(out, exist_ok=True)
    return out


def pick_base(host: str) -> str:
    """给主机挑一个能通的 base URL：优先 https，失败退 http。

    统一走 netutil.fetch（不抛异常），请求前做协议/边界校验：
    授权测试允许内网目标，故显式 allow_private=True 放行私网。
    """
    try:
        from modules import netutil
    except ImportError:
        import netutil
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            url = netutil.check_http_url(url, allow_private=True)
        except ValueError:
            continue
        r = netutil.fetch(url, timeout=10)
        if r.get("ok") and isinstance(r.get("status"), int) and r["status"] < 500:
            return url
    return f"https://{host}"


def cmd_all(args):
    target = args.target
    out = make_outdir(target)
    from modules.fingerprint import run_fingerprint
    from modules.api_unauth import run_api

    if is_ip(target):
        # ── IP 分支：反查域名 → 逐个 ICP → 指纹 → API 探测 ──
        from modules.reverse_ip import run_reverse
        from modules.icp import run_icp
        doms = _run_step("reverse", lambda: run_reverse(target, out))

        def _icp_loop():
            for d in (doms or [])[:5]:          # 备案查询最多查 5 个，避免限频
                try:
                    run_icp(d, out)
                except Exception as e:
                    print(f"[!] {d} 备案查询失败: {e}")
        _run_step("icp", _icp_loop, fatal=False)
        # 裸 IP 常被按域名路由的站点返回 404，优先用反查出的域名探测
        host = doms[0] if doms else target
        if doms:
            print(f"[*] 用反查域名 {host} 作为探测入口（裸 IP {target} 直连多为 404/默认页）")
        base = pick_base(host)
        print(f"[*] 目标站点探测 base = {base}")
        _run_step("fingerprint", lambda: run_fingerprint(base, out))
        _run_step("api", lambda: run_api(base, out))
        # ── 第二轮升级：端口扫描 + JS 情报（失败只警告，不阻断主流程）──
        from modules.portscan import run_portscan
        from modules.jsintel import run_jsintel
        _run_step("portscan", lambda: run_portscan(target, out), fatal=False)
        _run_step("jsintel", lambda: run_jsintel(base, out), fatal=False)
    else:
        # ── 域名分支：子域 → 存活验证 → 资产 → ICP → 指纹 → 路径 → API ──
        from modules.subdomain import run_subdomain, run_verify
        from modules.asset import run_asset
        from modules.icp import run_icp
        from modules.paths import run_paths
        _run_step("subdomain", lambda: run_subdomain(target, out))
        _run_step("verify", lambda: run_verify(out))      # 审计补充：证书日志含大量失效域名，必须验证存活
        _run_step("asset", lambda: run_asset(target, out))
        _run_step("icp", lambda: run_icp(target, out), fatal=False)
        base = pick_base(target)
        _run_step("fingerprint", lambda: run_fingerprint(base, out))
        _run_step("paths", lambda: run_paths(base, out))
        _run_step("api", lambda: run_api(base, out))
        # ── 第二轮升级：JS 情报提取 + 端口扫描（失败只警告，不阻断主流程）──
        from modules.jsintel import run_jsintel
        from modules.portscan import run_portscan
        _run_step("jsintel", lambda: run_jsintel(base, out), fatal=False)
        _run_step("portscan", lambda: run_portscan(target, out), fatal=False)
    # llm 步骤已整体移除（与 Go 引擎同步弃用）：不再把子域/资产/指纹/敏感路径
    # 打包发往任何第三方 LLM 服务，扫描数据不出本机。
    from modules.report import run_report
    _run_step("report", lambda: run_report(out, target))  # 聚合资产档案 + 证据包
    print(f"[+] 全流程完成，输出目录: {out}")


def main():
    p = argparse.ArgumentParser(prog="src-recon-tool", description="SRC 信息收集自动化工具（仅限授权测试）")
    p.add_argument("--progress-file", dest="progress_file", default="",
                   help="进度事件 JSONL 落盘路径（桌面壳用；空或环境变量 RECON_PROGRESS_FILE 均可）")
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
    pj = sub.add_parser("jsintel"); pj.add_argument("-u", "--url", required=True)
    pj.add_argument("--max-files", type=int, default=60, help="最多下载的外链 JS 数（默认 60，防失控）")
    pj.add_argument("--workers", type=int, default=6, help="下载并发（默认 6，低频克制）")
    pn = sub.add_parser("portscan"); pn.add_argument("-t", "--target", required=True, help="域名或 IP（仅限授权目标）")
    pn.add_argument("--ports", default="", help="如 80,443,8000-8100（默认内置常用端口表 ~100 个）")
    pn.add_argument("--timeout", type=float, default=1.5, help="单端口连接超时秒数（默认 1.5）")
    pn.add_argument("--workers", type=int, default=32, help="并发数（默认 32，上限 32）")
    pc = sub.add_parser("poc"); pc.add_argument("-t", "--target", required=True); pc.add_argument("-p", "--poc", required=True)
    pl = sub.add_parser("llm"); pl.add_argument("-d", "--domain", required=True)
    pr2 = sub.add_parser("report"); pr2.add_argument("-t", "--target", "-d", "--domain", dest="target",
                                                     required=True, help="按已有产出重新生成资产档案/证据包")
    args = p.parse_args()

    global _PROGRESS_FILE
    _PROGRESS_FILE = args.progress_file or os.environ.get("RECON_PROGRESS_FILE", "")
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    _emit("pipeline_start", "pipeline", args.cmd)
    if args.cmd != "all":
        _emit("start", args.cmd, "")
    try:
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
        elif args.cmd == "jsintel":
            from modules.jsintel import run_jsintel
            run_jsintel(args.url, make_outdir(args.url), workers=args.workers, max_files=args.max_files)
        elif args.cmd == "portscan":
            from modules.portscan import run_portscan
            run_portscan(args.target, make_outdir(args.target), ports=args.ports,
                         timeout=args.timeout, workers=args.workers)
        elif args.cmd == "poc":
            from modules.poc_engine import run_poc
            run_poc(args.target, args.poc)
        elif args.cmd == "llm":
            # 已弃用（与 Go 引擎 cli 同步）：LLM 辅助需向第三方服务发送资产数据，不再提供
            print("[*] llm 模块已弃用：为避免扫描数据外发第三方，该功能已移除（详见 README）")
            sys.exit(2)
        elif args.cmd == "report":
            from modules.report import run_report
            run_report(make_outdir(args.target), args.target)
        else:
            p.print_help()
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        if args.cmd != "all":
            _emit("fail", args.cmd, str(e))
        _emit("pipeline_end", "pipeline", "fail")
        raise
    else:
        if args.cmd != "all":
            _emit("done", args.cmd, "")
        _emit("pipeline_end", "pipeline", "done")


if __name__ == "__main__":
    main()
