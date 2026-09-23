# -*- coding: utf-8 -*-
"""资产档案 + 证据包：把一次侦察的各模块产出聚合成一份可读的 report.md，并把
out/evidence/ 下的取证目录打包成 zip（便于随提交稿一起交付）。

设计原则（沿用本仓库的审计纪律）：
  - 只写**实测**结果；缺失或未验证的项明确标注，不做推断；
  - report.md 里**不内联敏感值**（口令/会话/密钥），只给端点、状态码、大小、
    判定依据与证据目录 —— 敏感内容留在证据文件里，由使用者自行脱敏后引用；
  - 幂等：重复运行覆盖自己的产出，不追加、不重复计数。
"""
import datetime
import glob
import json
import os
import zipfile


def _read_json(path: str, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _read_lines(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


def collect(out: str, target: str) -> dict:
    """把各模块产出读进一个 dict（缺什么就少什么，不编造）。"""
    bundle = {
        "target": target,
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "reverse_domains": _read_lines(os.path.join(out, "reverse_domains.txt")),
        "subdomains": _read_lines(os.path.join(out, "subdomains.txt")),
        "subdomains_live": _read_json(os.path.join(out, "subdomains_live.json"), []),
        "icp": {},
        "fingerprint": _read_json(os.path.join(out, "fingerprint.json"), []),
        "paths": _read_json(os.path.join(out, "paths.json"), {}),
        "api": _read_json(os.path.join(out, "api_unauth.json"), {}),
        "assets": _read_lines(os.path.join(out, "assets.txt")),
        "llm_summary": "",
    }
    for p in sorted(glob.glob(os.path.join(out, "icp_*.json"))):
        d = _read_json(p, {})
        if isinstance(d, dict) and d.get("domain"):
            bundle["icp"][d["domain"]] = d
    p = os.path.join(out, "llm_summary.md")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            bundle["llm_summary"] = f.read()[:4000]
    return bundle


def render_md(b: dict) -> str:
    L = []
    a = L.append
    a(f"# 目标资产档案 · {b['target']}\n")
    a(f"- 生成时间：{b['generated_at']}")
    a(f"- 输出目录：`out/{b['target']}/`")
    a("- 声明：本档案仅记录**工具实测**结果；未验证项已标注，不含推断性结论\n")

    if b["reverse_domains"]:
        a("## 1. 归属线索\n")
        a("| 项 | 结果 |")
        a("|---|---|")
        a(f"| IP 反查域名 | {', '.join(b['reverse_domains'][:10])} |")
        for dom, d in list(b["icp"].items())[:5]:
            icp_no, unit = str(d.get("icp") or "").strip(), str(d.get("unit") or "").strip()
            # 纵深防御：不信任"看似 filed 实则脏数据"的记录（历史版本曾把限频写成备案号）
            valid = bool(d.get("filed")) and icp_no and "查询失败" not in icp_no and "查询失败" not in unit
            if valid:
                a(f"| ICP（{dom}） | {icp_no} · {unit} · {d.get('type') or '-'} · {d.get('time') or '-'} |")
            else:
                a(f"| ICP（{dom}） | 未查询到有效备案信息（{d.get('msg') or '接口未返回有效数据，建议人工复核'}） |")
        a("")

    subs = b["subdomains"]
    live_rows = [r for r in b["subdomains_live"] if r.get("alive")]
    if subs or live_rows:
        a("## 2. 子域与存活\n")
        a(f"- 枚举 {len(subs)} 个；DNS 可解析 **{len(live_rows)}** 个；"
          f"其中 {len([r for r in live_rows if r.get('http', {}).get('status')])} 个有 HTTP 响应")
        if live_rows:
            a("\n| 子域 | IP | HTTP | 标题 |")
            a("|---|---|---|---|")
            for r in live_rows[:30]:
                h = r.get("http", {})
                a(f"| {r['host']} | {','.join(r.get('ips', [])[:2])} | "
                  f"{h.get('scheme', '-')} {h.get('status', '-')} | {(h.get('title') or '')[:40]} |")
            if len(live_rows) > 30:
                a(f"| … | 其余 {len(live_rows) - 30} 条见 `subdomains_live.json` | | |")
        a("")

    if b["fingerprint"]:
        a("## 3. 指纹识别\n")
        a("| 命中 | 类型 |")
        a("|---|---|")
        for f_ in b["fingerprint"]:
            a(f"| {f_.get('name')} | {f_.get('type')} |")
        a("")

    pj = b["paths"] if isinstance(b["paths"], dict) else {}
    if pj.get("alive"):
        a("## 4. 敏感路径（已复验）\n")
        a("| 路径 | 状态 | 大小 | 复验 |")
        a("|---|---|---|---|")
        for r in pj["alive"]:
            a(f"| {r.get('path')} | {r.get('status')} | {r.get('size')}B | "
              f"{'通过' if r.get('verified') else '未通过'} |")
        note = pj.get("baseline", {})
        if note.get("kind") in ("soft404", "uniform403", "redirect"):
            a(f"\n> 注：该站存在 catch-all（{note['kind']}），形态一致的响应已被剔除。")
        a("")

    aj = b["api"] if isinstance(b["api"], dict) else {}
    hits = aj.get("hits") or []
    if hits:
        a("## 5. API 文档 / 未授权暴露\n")
        a("| 端点 | 名称 | 风险 | 存活复验 | 证据 |")
        a("|---|---|---|---|---|")
        for h in hits:
            ev = h.get("evidence_dir")
            a(f"| `{h.get('path')}` | {h.get('name')} | {h.get('risk')} | "
              f"{'存活 ✓' if h.get('live') else '未通过 ✗'} | "
              f"{'`' + os.path.relpath(ev, os.path.dirname(ev.rstrip(os.sep)) or '.') + '`' if ev else '—'} |")
        a(f"\n> catch-all 过滤：{aj.get('soft404_filtered', 0)} 条疑似被剔除；"
          f"存活命中 {aj.get('live_hits', 0)} 个（证据已落盘，**勿直接外传，脱敏后引用**）")
        a("")

    if b["llm_summary"]:
        a("## 6. LLM 辅助小结\n")
        a(b["llm_summary"])
        a("")

    a("## 待人工跟进\n")
    a("- [ ] 对上述存活项逐条复核（复核命令见各证据目录 `repro.md`）")
    a("- [ ] 对未复验通过的疑似项降低优先级，避免写进报告")
    a("- [ ] 结论只写实测内容；推演内容必须标注【推演】")
    return "\n".join(L)


def pack_evidence(out: str, target: str) -> str:
    """把 out/evidence/ 打包成 zip（无内容则返回空串）。"""
    src = os.path.join(out, "evidence")
    if not os.path.isdir(src):
        return ""
    files = []
    for root, _dirs, names in os.walk(src):
        for n in names:
            files.append(os.path.join(root, n))
    if not files:
        return ""
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in target)[:48] or "target"
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_path = os.path.join(out, f"evidence-{safe}-{ts}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for fp in files:
            z.write(fp, os.path.relpath(fp, out))       # 归档名相对 out/，不含绝对路径
    return zip_path


def run_report(out: str, target: str) -> str:
    b = collect(out, target)
    md = render_md(b)
    path = os.path.join(out, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[+] 资产档案已生成 -> {path}")
    zp = pack_evidence(out, target)
    if zp:
        n = len(zipfile.ZipFile(zp).namelist())
        print(f"[+] 证据包已打包（{n} 个文件，{os.path.getsize(zp) / 1024:.1f} KB）-> {zp}")
    else:
        print("[*] 本次没有落盘证据（无存活命中），跳过证据包")
    return path
