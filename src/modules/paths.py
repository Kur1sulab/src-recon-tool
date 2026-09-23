# -*- coding: utf-8 -*-
"""敏感路径探测（含软 404 基线 + 存活复验）。

审计修复要点：
  1) 先取站点基线（两个随机路径）：软 404 / 全局 403 / 统一跳转 →
     与该基线形态一致的响应一律不算"存活"（此前 SPA 站点会报满屏假存活）；
  2) 200 才算"可访问"；403/401 记为"被拒绝（可能受保护）"、30x 记为"跳转"，
     二者都不计入存活，避免把 WAF 的 catch-all 当战果；
  3) 命中的路径做 2 次复验，形态一致才记 verified=True（存活）。
仅做少量请求（字典可控），避免对目标造成压力。
"""
import json
import os

try:
    from . import netutil
except ImportError:
    import netutil

PATHS = [
    "/robots.txt", "/.git/config", "/.env", "/admin", "/admin/login",
    "/api/swagger", "/swagger-ui.html", "/v2/api-docs",
    "/wp-login.php", "/.svn/entries", "/.DS_Store",
    "/phpinfo.php", "/server-status", "/actuator", "/actuator/env",
    "/druid/index.html", "/backup.zip", "/www.zip", "/config.php.bak",
]


def run_paths(url: str, out: str) -> list:
    base = url.rstrip("/")
    bl = netutil.baseline(base)
    print(f"[*] 敏感路径探测: {url}（{len(PATHS)} 条字典）")
    print(f"[*] 站点基线: {bl.get('kind')}（随机路径 → {bl.get('status')}, {bl.get('size')}B）")
    if bl.get("kind") in ("soft404", "uniform403", "redirect"):
        print(f"[!] 存在 catch-all（{bl['kind']}），形态一致的响应不计入存活")
    alive, notes = [], []
    for p in PATHS:
        r = netutil.fetch(base + p)
        status, size = r.get("status"), r.get("size", 0)
        row = {"path": p, "status": status, "size": size, "ctype": r.get("ctype", ""),
               "final_url": r.get("final_url"), "shrunk": None}
        if status is None:
            continue
        if netutil.is_baseline(r, bl):
            row["verdict"] = "与基线一致（catch-all，忽略）"
            notes.append(row)
            continue
        if status == 200:
            v = netutil.verify_live(base + p)
            row["verdict"] = "可访问" if v["live"] else "200 但复验不一致（疑似瞬时）"
            row["verified"] = v["live"]
            row["recheck"] = v["attempts"]
            if v["live"]:
                alive.append(row)
        elif status in (401, 403):
            row["verdict"] = "被拒绝（可能受保护/WAF）"
            notes.append(row)
        elif status in (301, 302):
            row["verdict"] = f"跳转 → {row.get('final_url')}"
            notes.append(row)
    path = os.path.join(out, "paths.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"base": url, "baseline": bl, "alive": alive, "notes": notes}, f,
                  ensure_ascii=False, indent=2)
    print(f"[+] 敏感路径探测完成（存活 {len(alive)} 个，另有 {len(notes)} 条被拒绝/跳转/基线过滤）-> {path}")
    for row in alive:
        print(f"      [可访问] {row['path']}  ({row['status']}, {row['size']}B, 复验通过)")
    return alive


if __name__ == "__main__":
    import sys
    run_paths(sys.argv[1], "out")
