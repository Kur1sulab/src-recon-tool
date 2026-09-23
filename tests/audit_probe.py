# -*- coding: utf-8 -*-
"""审计驱动：起 mock 靶站 → 对每个场景跑 api / paths 模块 → 打印判定结果。

期望（审计基准）:
  soft404 / waf / loginredirect / api404  →  两个模块都应 0 命中（这些是误报陷阱）
  real                                    →  api 命中 7 个真暴露、paths 命中真敏感路径
  empty                                   →  两者都 0 命中（对照组）
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from mock_server import serve                      # noqa: E402
from modules import api_unauth, paths as paths_mod  # noqa: E402

PORT = 8799
OUT = os.path.join(ROOT, "out", "_audit")


def run_api(base):
    msg = []
    orig = print
    try:
        globals()["print"] = lambda *a, **k: msg.append(" ".join(str(x) for x in a))
        hits = api_unauth.run_api(base, OUT)
    finally:
        globals()["print"] = orig
    return hits, "\n".join(msg)


def run_paths(base):
    msg = []
    orig = print
    try:
        globals()["print"] = lambda *a, **k: msg.append(" ".join(str(x) for x in a))
        alive = paths_mod.run_paths(base, OUT)
    finally:
        globals()["print"] = orig
    return alive, "\n".join(msg)


def main():
    os.makedirs(OUT, exist_ok=True)
    srv = serve(PORT)
    print(f"mock 靶站已起: http://127.0.0.1:{PORT}\n")
    scenarios = ["soft404", "api404", "waf", "loginredirect", "empty", "real"]
    summary = {}
    for sc in scenarios:
        base = f"http://127.0.0.1:{PORT}/{sc}"
        hits, _ = run_api(base)
        found, _ = run_paths(base)
        summary[sc] = (len(hits), len(found))
        print(f"── 场景 {sc:<14} api 命中 {len(hits):>2} | paths 存活 {len(found):>2}")
        if hits:
            for h in hits[:6]:
                print(f"      api  [{h.get('risk')}] {h['name']} {h['path']}  ({h.get('evidence')})")
        if found and sc != "real":
            print(f"      paths 误报样本: {[f['path'] for f in found[:6]]}")
        if sc == "real":
            print(f"      paths 真命中: {[f['path'] for f in found]}")
    srv.shutdown()
    print("\n── 审计结论 ──")
    for sc, (a, p) in summary.items():
        expect_zero = sc != "real"
        flag_a = "✗ 误报!" if (expect_zero and a > 0) else "✓"
        flag_p = "✗ 误报!" if (expect_zero and p > 0) else "✓"
        print(f"  {sc:<14} api {a:>2} {flag_a}   paths {p:>2} {flag_p}")


if __name__ == "__main__":
    main()
