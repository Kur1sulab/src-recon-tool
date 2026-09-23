# -*- coding: utf-8 -*-
"""探测公共底座：软 404 基线识别 + 存活复验。

为什么需要它（审计发现）：
  1) SPA / 自定义错误页 / API 网关的 catch-all 会对**任意路径**返回 200，
     单发探测会把它们全部当成"命中"——必须先取基线再比对；
  2) 全局 403（WAF/权限网关）与 302 跳登录同理，形态一致的响应一律不算命中；
  3) "命中"必须复验：连续 2 次请求都能稳定复现，才记为存活（liveness）。
"""
import hashlib
import random
import ssl
import string
import urllib.error
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}
_RAND = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))


def fetch(url: str, timeout: int = 12, follow: bool = True, max_bytes: int = 200000) -> dict:
    """单次请求，返回结构化结果（不抛异常）。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = {"ok": False, "url": url, "status": None, "final_url": url, "size": 0,
           "sha1": "", "ctype": "", "body": "", "headers": {}}
    try:
        req = urllib.request.Request(url, headers=_UA)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler() if follow
                                             else urllib.request.HTTPHandler)
        with opener.open(req, timeout=timeout) as r:          # type: ignore[attr-defined]
            raw = r.read(max_bytes)
            out.update(ok=True, status=r.status, size=len(raw),
                       sha1=hashlib.sha1(raw).hexdigest()[:16],
                       ctype=r.headers.get("Content-Type", ""),
                       body=raw.decode("utf-8", "ignore"),
                       final_url=r.geturl(),
                       headers={k.lower(): v for k, v in r.headers.items()})
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(max_bytes)
        except Exception:
            pass
        out.update(ok=True, status=e.code, size=len(raw), sha1=hashlib.sha1(raw).hexdigest()[:16],
                   ctype=e.headers.get("Content-Type", "") if e.headers else "",
                   body=raw.decode("utf-8", "ignore"), final_url=e.geturl() if hasattr(e, "geturl") else url)
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def same_shape(a: dict, b: dict) -> bool:
    """两次响应的"形态"是否一致（用于识别 catch-all：状态码 + 内容指纹/长度+类型）。"""
    if not a or not b:
        return False
    if a.get("status") != b.get("status"):
        return False
    if a.get("sha1") and a.get("sha1") == b.get("sha1"):
        return True
    return bool(a.get("size")) and a.get("size") == b.get("size") and a.get("ctype") == b.get("ctype")


def baseline(base_url: str, timeout: int = 12) -> dict:
    """取两个随机不存在路径的响应，判断站点是否存在 catch-all 行为。

    返回 {"kind": soft404|uniform403|redirect|normal|unknown, "status", "sha1", "size", "ctype",
          "final_url", "samples": n}
    """
    base = base_url.rstrip("/")
    probes = [fetch(f"{base}/_{_RAND}{i}", timeout=timeout) for i in (1, 2)]
    ok = [p for p in probes if p.get("ok")]
    if len(ok) < 2:
        return {"kind": "unknown", "samples": len(ok)}
    kind = "normal"
    if same_shape(ok[0], ok[1]):
        st = ok[0].get("status")
        if st == 200:
            kind = "soft404"
        elif st in (401, 403):
            kind = "uniform403"
        elif st in (301, 302):
            kind = "redirect"
    return {"kind": kind, "status": ok[0].get("status"), "sha1": ok[0].get("sha1"),
            "size": ok[0].get("size"), "ctype": ok[0].get("ctype"),
            "final_url": ok[0].get("final_url"), "samples": 2}


def is_baseline(resp: dict, base: dict) -> bool:
    """该响应是否只是站点的 catch-all（软 404 / 全局 403 / 统一跳转）？"""
    if not base or base.get("kind") in (None, "normal", "unknown"):
        return False
    if base.get("kind") == "redirect":
        return resp.get("final_url") != resp.get("url")        # 被统一重定向走 = 不算命中
    return same_shape(resp, {"status": base.get("status"), "sha1": base.get("sha1"),
                             "size": base.get("size"), "ctype": base.get("ctype")})


def verify_live(url: str, tries: int = 2, timeout: int = 12, expect_body: str = None) -> dict:
    """存活复验：连续 tries 次请求，两次形态一致且仍然命中特征 → live=True。"""
    attempts = []
    for _ in range(max(1, tries)):
        r = fetch(url, timeout=timeout)
        attempts.append({"status": r.get("status"), "size": r.get("size"), "sha1": r.get("sha1")})
        if expect_body and expect_body.lower() not in (r.get("body") or "").lower():
            return {"live": False, "attempts": attempts, "note": "复验时特征消失"}
        if not r.get("ok") or r.get("status") != attempts[0]["status"]:
            return {"live": False, "attempts": attempts, "note": "复验状态码不一致"}
    consistent = all(a["sha1"] and a["sha1"] == attempts[0]["sha1"] for a in attempts) or \
                 all(a["size"] == attempts[0]["size"] for a in attempts)
    return {"live": bool(consistent), "attempts": attempts,
            "note": "两次一致" if consistent else "两次响应不一致（疑似瞬时/WAF 抖动）"}
