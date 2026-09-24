# -*- coding: utf-8 -*-
"""JS 情报提取（前端接口挖掘）：从目标页面的 JavaScript 中挖攻击面线索。

流程：抓目标页 → 收集 <script src> 外链 + 内联 JS → 低并发下载外链
（≤6 并发 / 单文件 ≤2MB / 10s 超时 / 只 GET / 普通浏览器 UA）→ 三类线索：
  a) API 端点/路径：fetch/axios/$.ajax 调用 + 字符串字面量中的路径；
     去重 + 规范化 + 滤静态资源；endpoints_full（绝对 URL）可直接喂给
     api / paths 模块复核；
  b) 敏感线索（只标位置，不判定漏洞）：key/secret/token/password/appid/
     authorization/ak/sk 命中的 文件+行号+片段（前 40 字符）；
     疑似值只留前 4 位其余打码——片段里的值同样打码，保证输出文件本身不泄露敏感值；
  c) 域名线索：JS 中绝对 URL 的域名 / 内网 IP / 子域名（相对目标归类，去重）。

输出 out/<target>/jsintel.json + jsintel.txt（落盘统一走 netutil.safe_write：
目录白名单清洗 + 文件名固定 + 越界校验，杜绝目录穿越）。
纪律：线索 ≠ 漏洞，所有命中必须人工复核；本模块只发 GET，不发任何写请求。
"""
import bisect
import ipaddress
import json
import re
from urllib.parse import urljoin, urlsplit

try:                                  # 作为包导入时（tests / recon.py）用相对导入
    from . import netutil
except ImportError:                   # 直接执行本文件时的兜底
    import netutil

MAX_FILE_BYTES = 2_000_000            # 单个 JS 文件下载上限 ~2MB
DEFAULT_WORKERS = 6                   # 低并发（对目标友好，WAF 也友好）
DEFAULT_TIMEOUT = 10                  # 单文件下载超时
DEFAULT_MAX_FILES = 60                # 最多下载的外链 JS 数（防失控）

# 静态资源后缀：出现在端点线索里的一律丢弃
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
               ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp3", ".mp4",
               ".webm", ".webp", ".wav", ".pdf", ".zip", ".gz", ".wasm", ".cur")

_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_SCRIPT_INLINE_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
# fetch(...) / axios.xxx(...) / axios(...) / $.get|post|ajax|getJSON(...)
_CALL_URL_RE = re.compile(
    r"""(?:\bfetch\s*\(|\baxios(?:\s*\.\s*\w+\s*\(|\s*\()|\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\()"""
    r"""\s*["'`]([^"'`\s]{2,200}?)["'`]""", re.I)
_URL_KEY_RE = re.compile(r"""\burl\s*[:=]\s*["'`](/[^"'`\s]{2,160})["'`]""", re.I)
# 字符串字面量里的路径（以 / 开头）
_LITERAL_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_][A-Za-z0-9_\-./~]{1,150})["'`]""")
# 绝对 URL 的 host（http(s):// 或协议相对 //）
_ABS_HOST_RE = re.compile(
    r"""(?:https?:)?//([A-Za-z0-9][A-Za-z0-9._-]*)(?::\d{2,5})?(?:[/"'`\s<>\\)\]},;]|$)""")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# 敏感键（长形式在前，避免 alternation 短路）；值打码后入库
_SECRET_RE = re.compile(
    r"""(?i)\b(access[_-]?key|api[_-]?key|apikey|app[_-]?key|app[_-]?secret|appid|app_id|"""
    r"""secret[_-]?key|authorization|passwd|password|secret|token|ak|sk)\b"""
    r"""["'`]?\s*[:=]\s*["'`]?([^"'`\s;,&<>]{4,120})""")
_SECRET_VALUE_BLOCKLIST = {"undefined", "null", "true", "false", "none",
                           "password", "token", "secret", "xxxx"}


def mask_value(v: str) -> str:
    """疑似值打码：只留前 4 位，其余换成 ****（≤4 位全打码）。"""
    v = (v or "").strip()
    return (v[:4] + "****") if len(v) > 4 else "****"


def _printable_ratio(s: str) -> float:
    """前 4KB 的可打印比例（识别二进制 / WAF 挑战页，避免把乱码当 JS 解析）。"""
    if not s:
        return 1.0
    s = s[:4000]
    ok = sum(1 for c in s if c.isprintable() or c in "\t\r\n")
    return ok / len(s)


def extract_scripts(html: str, page_url: str) -> tuple:
    """HTML → (外链 JS 绝对 URL 列表, 内联代码 [(label, text)])。"""
    ext, seen = [], set()
    for src in _SCRIPT_SRC_RE.findall(html or ""):
        src = src.strip()
        if not src or src.lower().startswith(("data:", "javascript:")):
            continue
        u = urljoin(page_url, src)
        p = urlsplit(u).path.lower()
        if p.endswith(_STATIC_EXT) and not p.endswith(".js"):
            continue                              # 浏览器虽会请求，但对情报无价值，省掉
        if u not in seen:
            seen.add(u)
            ext.append(u)
    inline = []
    for i, m in enumerate(_SCRIPT_INLINE_RE.finditer(html or "")):
        body = (m.group(1) or "").strip()
        if len(body) >= 8:                            # 过滤 <script src> 的空体
            inline.append((f"inline#{i + 1}", body))
    return ext, inline


def normalize_endpoint(raw: str) -> str:
    """端点线索规范化：去 query/fragment、绝对 URL 只留 path、补前导斜杠、滤静态资源。

    不合格返回空串。这里是把"假线索"挡在输出之外的第一道闸。
    """
    s = (raw or "").strip().strip("\"'")
    if not s or "{" in s or "}" in s:                 # 模板占位符 / 动态拼接，不可复跑
        return ""
    if "://" in s:                                    # 绝对 URL：host 记入域名线索，这里只留 path
        try:
            s = urlsplit(s).path or ""
        except ValueError:
            return ""
        if not s or s == "/":
            return ""
    if not s.startswith("/"):
        s = "/" + s
    s = s.split("?", 1)[0].split("#", 1)[0]
    if len(s) > 2 and s.endswith("/"):
        s = s.rstrip("/")
    if len(s) < 2 or not re.search(r"[A-Za-z0-9]", s):
        return ""
    if s.lower().endswith(_STATIC_EXT):               # 静态资源不是攻击面入口
        return ""
    return s


def extract_endpoints(text: str) -> list:
    """JS 源码 → 排序去重后的端点路径列表（可直接拼 base 喂给 api/paths 模块）。"""
    eps = set()
    for rx in (_CALL_URL_RE, _URL_KEY_RE, _LITERAL_PATH_RE):
        for m in rx.finditer(text or ""):
            e = normalize_endpoint(m.group(1))
            if e:
                eps.add(e)
    return sorted(eps)[:800]


def extract_sensitive(text: str, source: str, cap: int = 200) -> list:
    """敏感线索：只标位置（文件+行号+片段前 40 字符），值打码（片段内同步打码）。"""
    rows, seen = [], set()
    text = text or ""
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    lines = text.splitlines()
    line_cache = {}

    def _masked_line(li):
        """整行先做全量打码再截 40 字符——同一行里相邻敏感键的值也要打掉（审计发现）。"""
        if li not in line_cache:
            ln = lines[li] if li < len(lines) else ""
            for m2 in _SECRET_RE.finditer(ln):
                ln = ln.replace(m2.group(2), mask_value(m2.group(2)))
            line_cache[li] = ln
        return line_cache[li]

    for m in _SECRET_RE.finditer(text):
        key, val = m.group(1).lower(), m.group(2)
        if val.lower() in _SECRET_VALUE_BLOCKLIST or val.lower().startswith("${"):
            continue
        if val.isdigit() and len(val) < 8:            # 纯数字短串基本是枚举/计数，不是密钥
            continue
        masked = mask_value(val)
        li = max(0, bisect.bisect_right(starts, m.start()) - 1)
        snippet = _masked_line(li).strip()[:40]       # 片段里不能留任何全量值（隐私纪律）
        k = (source, li + 1, key)
        if k in seen:
            continue
        seen.add(k)
        rows.append({"file": source, "line": li + 1, "key": key,
                     "value": masked, "snippet": snippet})
        if len(rows) >= cap:
            break
    return rows


def extract_domains(text: str, target_host: str) -> dict:
    """JS 源码 → 域名线索（相对目标域名归类；内网 IP 单列；公网 IP 不收，防版本号误报）。"""
    hosts, ips = set(), set()
    text = text or ""
    for m in _ABS_HOST_RE.finditer(text):
        h = m.group(1).lower()
        if "." in h and not re.fullmatch(r"[\d.]+", h):
            hosts.add(h)
    for m in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            ips.add(m.group(1))
    t = (target_host or "").lower().strip(".")
    sub = sorted(d for d in hosts if t and (d == t or d.endswith("." + t)))
    third = sorted(d for d in hosts if d not in set(sub))
    return {"subdomains": sub, "thirdparty": third, "internal_ips": sorted(ips)}


def download_scripts(urls: list, workers: int = DEFAULT_WORKERS,
                     timeout: int = DEFAULT_TIMEOUT, max_files: int = DEFAULT_MAX_FILES) -> list:
    """低并发下载外链 JS（≤6 并发 / 只 GET / 单文件 ≤2MB）；返回与输入同序的结果列表。"""
    import concurrent.futures
    urls = list(urls)[:max(0, max_files)]
    if not urls:
        return []
    results = [None] * len(urls)

    def _one(item):
        i, u = item
        r = netutil.fetch(u, timeout=timeout, max_bytes=MAX_FILE_BYTES)
        row = {"url": u, "status": r.get("status"), "ok": bool(r.get("ok")),
               "error": r.get("error", ""), "text": r.get("body", "") if r.get("ok") else ""}
        if row["text"] and _printable_ratio(row["text"]) < 0.5:
            row["text"] = ""
            row["error"] = "非文本内容（疑似二进制/WAF 挑战页），跳过解析"
        return i, row

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, DEFAULT_WORKERS))) as ex:
        for i, row in ex.map(_one, enumerate(urls)):   # map 保序，各线程只写自己的槽位（并发安全）
            results[i] = row
    return results


def render_txt(r: dict) -> str:
    L = []
    a = L.append
    sc = r.get("scripts", {})
    a(f"# JS 情报清单 — {r['base']}")
    a(f"- 页面状态: {r.get('page_status')}")
    a(f"- 外链 JS: {sc.get('external', 0)}（下载成功 {sc.get('downloaded', 0)} / 失败 {sc.get('failed', 0)}），"
      f"内联 {sc.get('inline', 0)} 段")
    a("- 声明: 线索≠漏洞，需人工复核；疑似值已打码（只留前 4 位）\n")

    eps = r.get("endpoints", [])
    a(f"## API 端点线索（{len(eps)} 条）")
    a("以下绝对 URL 已规范化去重，可直接喂给 api / paths 模块复核：")
    for u in r.get("endpoints_full", []):
        a(f"  {u}")
    a("")

    sen = r.get("sensitive", [])
    a(f"## 敏感线索（{len(sen)} 处，仅位置提示，值为打码）")
    for s in sen:
        a(f"- [{s['file']}:{s['line']}] {s['key']} = {s['value']}  |  `{s['snippet']}`")
    if not sen:
        a("- （未命中）")
    a("")

    d = r.get("domains", {})
    a("## 域名线索")
    a(f"- 子域/同域: {', '.join(d.get('subdomains', [])) or '-'}")
    a(f"- 第三方域: {', '.join(d.get('thirdparty', [])) or '-'}")
    a(f"- 内网 IP: {', '.join(d.get('internal_ips', [])) or '-'}")
    return "\n".join(L) + "\n"


def run_jsintel(url: str, out: str, workers: int = DEFAULT_WORKERS,
                max_files: int = DEFAULT_MAX_FILES, timeout: int = DEFAULT_TIMEOUT) -> dict:
    print(f"[*] JS 情报提取: {url}（外链并发 ≤{DEFAULT_WORKERS}，单文件 ≤{MAX_FILE_BYTES // 1_000_000}MB，只 GET）")
    result = {"base": url, "page_status": None, "error": "",
              "scripts": {"external": 0, "inline": 0, "downloaded": 0, "failed": 0},
              "endpoints": [], "endpoints_full": [], "sensitive": [],
              "domains": {"subdomains": [], "thirdparty": [], "internal_ips": []}}
    page = netutil.fetch(url, timeout=max(12, timeout))
    result["page_status"] = page.get("status")
    # 只有 200（含跳转后的最终页）才值得挖 JS；403/404/WAF 拦截页 → 优雅降级输出空结果
    if not page.get("ok") or page.get("status") != 200 or not page.get("body"):
        result["error"] = page.get("error") or (f"HTTP {page.get('status')}"
                                                if page.get("status") else "响应无内容")
        print(f"[!] 页面抓取失败（status={page.get('status')} {page.get('error') or ''}），"
              f"输出空结果（WAF/不可达属正常，优雅降级）")
        _save(out, result)
        return result

    final = page.get("final_url") or url
    parts = urlsplit(final)
    netloc = (parts.netloc or "").lower()
    host = netloc.split(":")[0]
    scheme = "https" if parts.scheme == "https" else "http"
    ext, inline = extract_scripts(page["body"], final)
    print(f"[*] 页面 status={page.get('status')}，外链 JS {len(ext)} 个，内联 {len(inline)} 段")

    sources = [(label, text) for label, text in inline]
    dl = download_scripts(ext, workers=workers, timeout=timeout, max_files=max_files)
    ok_rows = [d for d in dl if d["ok"] and d["text"]]
    fail_rows = [d for d in dl if not (d["ok"] and d["text"])]
    if fail_rows:
        print(f"[!] {len(fail_rows)} 个外链 JS 未取得内容（4xx/超时/二进制，已跳过并记录）")
    for d in ok_rows:
        sources.append((urlsplit(d["url"]).path or d["url"], d["text"]))

    endpoints, sensitive, seen = set(), [], set()
    for label, text in sources:
        endpoints.update(extract_endpoints(text))
        for f in extract_sensitive(text, label):
            k = (f["file"], f["line"], f["key"])
            if k not in seen:
                seen.add(k)
                sensitive.append(f)
    endpoints = sorted(endpoints)

    result["scripts"] = {"external": len(ext), "inline": len(inline),
                         "downloaded": len(ok_rows), "failed": len(fail_rows)}
    result["endpoints"] = endpoints
    result["endpoints_full"] = [f"{scheme}://{netloc}{e}" for e in endpoints] if netloc else []
    result["sensitive"] = sensitive
    result["domains"] = extract_domains("\n".join(t for _l, t in sources), host)

    _save(out, result)
    d = result["domains"]
    print(f"[+] 端点线索 {len(endpoints)} 条 / 敏感线索 {len(sensitive)} 条 / "
          f"子域 {len(d['subdomains'])} · 第三方域 {len(d['thirdparty'])} · 内网 IP {len(d['internal_ips'])}")
    for e in endpoints[:10]:
        print(f"      [端点] {e}")
    for s in sensitive[:8]:
        print(f"      [敏感] {s['file']}:{s['line']}  {s['key']}={s['value']}（已打码）")
    return result


def _save(out: str, result: dict) -> None:
    # 落盘统一走 netutil.safe_write：目录白名单清洗 + 纯文件名 + 规范化越界校验
    p = netutil.safe_write(out, "jsintel.json", json.dumps(result, ensure_ascii=False, indent=2))
    netutil.safe_write(out, "jsintel.txt", render_txt(result))
    print(f"[+] JS 情报完成 -> {p}")


if __name__ == "__main__":
    import sys
    run_jsintel(sys.argv[1], "out")
