# -*- coding: utf-8 -*-
"""探测公共底座：软 404 基线识别 + 存活复验。

为什么需要它（审计发现）：
  1) SPA / 自定义错误页 / API 网关的 catch-all 会对**任意路径**返回 200，
     单发探测会把它们全部当成"命中"——必须先取基线再比对；
  2) 全局 403（WAF/权限网关）与 302 跳登录同理，形态一致的响应一律不算命中；
  3) "命中"必须复验：连续 2 次请求都能稳定复现，才记为存活（liveness）。
"""
import hashlib
import secrets
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}
_RAND = secrets.token_hex(5)          # 基线探针随机串（secrets 源，替代 random）


def fetch(url: str, timeout: int = 12, follow: bool = True, max_bytes: int = 200000,
          method: str = None, data=None, headers: dict = None) -> dict:
    """单次 HTTP 请求，返回结构化结果（不抛异常）。

    各模块的统一请求底座：内部只走 opener.open，不经 urlopen；协议白名单
    http/https 在入口处把关（非拦截式，返回 error 字段，保持"不抛异常"契约）。
    method/data/headers 供 POST 类调用（POC 引擎、LLM）使用，默认 GET。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = {"ok": False, "url": url, "status": None, "final_url": url, "size": 0,
           "digest": "", "ctype": "", "body": "", "headers": {}}
    try:
        if urlsplit(url).scheme not in ("http", "https"):
            out["error"] = "仅允许 http/https 协议"
            return out
    except ValueError:
        out["error"] = "非法 URL"
        return out
    hdrs = dict(_UA)
    hdrs.update(headers or {})
    try:
        req = urllib.request.Request(url, headers=hdrs, data=data, method=method)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler() if follow
                                             else urllib.request.HTTPHandler)
        with opener.open(req, timeout=timeout) as r:          # type: ignore[attr-defined]
            raw = r.read(max_bytes)
            out.update(ok=True, status=r.status, size=len(raw),
                       digest=hashlib.sha256(raw).hexdigest()[:16],
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
        out.update(ok=True, status=e.code, size=len(raw), digest=hashlib.sha256(raw).hexdigest()[:16],
                   ctype=e.headers.get("Content-Type", "") if e.headers else "",
                   body=raw.decode("utf-8", "ignore"), final_url=e.geturl() if hasattr(e, "geturl") else url)
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def safe_filename(s: str) -> str:
    """文件名白名单清洗（仓库统一纪律，同取证目录 _safe）：只保留字母数字与 . _ -，
    其余一律换 _，去掉首尾点号——外部可控字符串（如域名）进文件名前必须过这里。
    fix1 P2（与 Go SafeFilename 同步）：Windows 保留设备名主干（con/prn/aux/nul/
    com1-9/lpt1-9，任意扩展名组合皆保留）命中后在主干后补 _（con.txt → con_.txt）。
    """
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9._-]", "_", (s or ""))[:64].strip(".")
    if not s:
        return "unknown"
    stem, dot, ext = s.partition(".")
    if stem.lower() in {"con", "prn", "aux", "nul",
                        *[f"com{i}" for i in range(1, 10)],
                        *[f"lpt{i}" for i in range(1, 10)]}:
        s = stem + "_" + dot + ext
    return s


def _redact_url(u: str) -> str:
    """fix3（audit low#8）：query 可能携带 api-key 等凭据，错误信息只保留到
    path 为止，不回显 query（与 Go urlcheck.go 同步脱敏）。"""
    for ch in ("?", "#"):
        i = u.find(ch)
        if i >= 0:
            return u[:i] + "?…"
    return u


def check_http_url(url: str, allow_private: bool = False) -> str:
    """请求前 URL 边界校验（SSRF 纪律）：
      1) 只放行 http/https 远程协议——杜绝 file:// 等本地协议被拼进探测目标；
      2) 解析主机并做 IP 边界检查：默认阻断 私网/环回/链路本地/保留 地址；
         本工具面向**授权**测试（内网资产/本机靶标可以是合法目标），由调用方
         显式传 allow_private=True 放行——放行必须是显式决定，不做静默默认。

    返回校验后的 URL；非法或越界抛 ValueError。
    注：解析与实际建连之间存在 TOCTOU 窗口（DNS rebinding），本工具以
    "只向使用者显式指定的目标发请求" 的使用纪律兜底，不做每请求地址 pin。
    """
    import ipaddress as _ip
    import socket as _socket
    from urllib.parse import urlsplit as _split
    u = (url or "").strip()
    try:
        p = _split(u)
    except ValueError:
        raise ValueError(f"非法 URL: {_redact_url(u)!r}")
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"非法探测目标（仅允许 http/https 远程地址）: {u[:80]!r}")
    host = p.hostname
    if not host:
        raise ValueError(f"URL 缺少主机名: {u[:80]!r}")
    try:
        infos = _socket.getaddrinfo(host, None)
    except OSError:
        raise ValueError(f"目标主机无法解析: {host}")
    if not allow_private:
        for info in infos:
            ip = _ip.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError(f"目标 {host} 解析到内网/保留地址 {info[4][0]}，已阻断"
                                 f"（授权内网目标请显式 allow_private=True）")
    return u


def safe_outdir(out: str) -> str:
    """输出目录纵深防御：剔除 ../ 与 . 悬浮组件后再用（禁止目录穿越）。

    out 可能来自外部参数（CLI/上层编排），与取证目录的白名单清洗同属仓库
    目录穿越纪律：文件名本身是模块内常量，但目录仍必须先规范化校验。
    """
    import os as _os
    import re as _re
    out = (out or "").strip() or "out"
    drive, tail = _os.path.splitdrive(out)
    parts = [p for p in _re.split(r"[\\/]+", tail) if p not in ("", ".", "..")]
    if not parts:
        return _os.path.join("out", "unknown")
    root = (drive + _os.sep) if drive else (_os.sep if out.startswith(("/", "\\")) else "")
    return _os.path.normpath(root + _os.sep.join(parts))


def safe_subdir(out: str, *parts: str) -> str:
    """在 out 下构造多级子目录：每一级都过 safe_filename 白名单，最后 commonpath
    校验仍限于 out 内才创建。用于证据目录 out/evidence/<host>/<slug>/ 这类
    外部可控成分的多级拼接（目录穿越纪律的目录版）。"""
    import os as _os
    import pathlib as _pl
    base = _pl.Path(_os.path.abspath(safe_outdir(out)))
    cur = base
    for p in parts:
        cur = cur / safe_filename(p)
    if _os.path.commonpath([str(base), str(cur.resolve())]) != str(base):
        raise ValueError(f"输出路径越界: {cur}")
    cur.mkdir(parents=True, exist_ok=True)
    return str(cur)


def safe_write(out: str, name: str, content: str) -> str:
    """各模块落盘统一收口：out 先过 safe_outdir 白名单清洗，name 必须是纯文件名
    （再过 safe_filename 白名单），最终路径规范化后校验仍限于 out 内才写入。

    返回最终绝对路径；越界/非法文件名抛 ValueError。目录穿越纪律的统一实现。
    """
    import os as _os
    import pathlib as _pl
    base = _pl.Path(_os.path.abspath(safe_outdir(out)))
    if not name or _pl.PurePath(name).name != name:
        raise ValueError(f"非法文件名: {name!r}")
    final = base / safe_filename(name)
    if _os.path.commonpath([str(base), str(final.resolve())]) != str(base):
        raise ValueError(f"输出路径越界: {final}")
    final.parent.mkdir(parents=True, exist_ok=True)
    final.write_text(content, encoding="utf-8")
    return str(final)


def same_shape(a: dict, b: dict) -> bool:
    """两次响应的"形态"是否一致（用于识别 catch-all：状态码 + 内容指纹/长度+类型）。"""
    if not a or not b:
        return False
    if a.get("status") != b.get("status"):
        return False
    if a.get("digest") and a.get("digest") == b.get("digest"):
        return True
    return bool(a.get("size")) and a.get("size") == b.get("size") and a.get("ctype") == b.get("ctype")


def baseline(base_url: str, timeout: int = 12) -> dict:
    """取两个随机不存在路径的响应，判断站点是否存在 catch-all 行为。

    返回 {"kind": soft404|uniform403|redirect|normal|unknown, "status", "digest", "size", "ctype",
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
    return {"kind": kind, "status": ok[0].get("status"), "digest": ok[0].get("digest"),
            "size": ok[0].get("size"), "ctype": ok[0].get("ctype"),
            "final_url": ok[0].get("final_url"), "samples": 2}


def is_baseline(resp: dict, base: dict) -> bool:
    """该响应是否只是站点的 catch-all（软 404 / 全局 403 / 统一跳转）？"""
    if not base or base.get("kind") in (None, "normal", "unknown"):
        return False
    if base.get("kind") == "redirect":
        return resp.get("final_url") != resp.get("url")        # 被统一重定向走 = 不算命中
    return same_shape(resp, {"status": base.get("status"), "digest": base.get("digest"),
                             "size": base.get("size"), "ctype": base.get("ctype")})


def verify_live(url: str, tries: int = 2, timeout: int = 12, expect_body: str = None) -> dict:
    """存活复验：连续 tries 次请求，两次形态一致且仍然命中特征 → live=True。"""
    attempts = []
    for _ in range(max(1, tries)):
        r = fetch(url, timeout=timeout)
        attempts.append({"status": r.get("status"), "size": r.get("size"), "digest": r.get("digest")})
        if expect_body and expect_body.lower() not in (r.get("body") or "").lower():
            return {"live": False, "attempts": attempts, "note": "复验时特征消失"}
        if not r.get("ok") or r.get("status") != attempts[0]["status"]:
            return {"live": False, "attempts": attempts, "note": "复验状态码不一致"}
    consistent = all(a["digest"] and a["digest"] == attempts[0]["digest"] for a in attempts) or \
                 all(a["size"] == attempts[0]["size"] for a in attempts)
    return {"live": bool(consistent), "attempts": attempts,
            "note": "两次一致" if consistent else "两次响应不一致（疑似瞬时/WAF 抖动）"}
