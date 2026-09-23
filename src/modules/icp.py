# -*- coding: utf-8 -*-
"""ICP 备案查询：域名 → 备案号 / 主办单位 / 备案类型 / 审核日期。

数据源：apihz 公开接口（cn.apihz.cn，2026-09 实测可用）。
demo 额度（id/key = 88888888）为官方公开示例，频次有限；
生产使用建议去 apihz 申请自己的 id/key，并用环境变量覆盖：
  APIHZ_ID / APIHZ_KEY
输出 icp.json（未备案时记录 {"code": 400, ...} 原样保留，便于举证）。
"""
import json
import os
import time
import urllib.request

_API = "https://cn.apihz.cn/api/wangzhan/icp.php"
_UA = {"User-Agent": "src-recon-tool/1.0 (+authorized-testing-only)"}


def parse_icp(payload) -> dict:
    """把接口返回归一化。已备案 → {filed: True, icp, unit, type, domain, time}；
    未备案/失败 → {filed: False, msg}。接受 dict 或 JSON 文本。"""
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except Exception:
            return {"filed": False, "msg": "响应非 JSON"}
    if not isinstance(payload, dict):
        return {"filed": False, "msg": "响应格式异常"}
    if payload.get("code") == 200:
        icp = (payload.get("icp") or "").strip()
        unit = (payload.get("unit") or "").strip()
        # apihz 限频时会返回 code=200 但字段值为「查询失败」，必须挡掉，否则会把限频写成备案号
        if not icp or "查询失败" in icp or "查询失败" in unit:
            return {"filed": False, "msg": payload.get("msg") or "接口未返回有效备案数据（多为限频，稍后重试）"}
        return {"filed": True, "icp": icp, "unit": unit,
                "type": payload.get("type"), "domain": payload.get("domain"),
                "time": payload.get("time")}
    return {"filed": False, "msg": payload.get("msg") or "查询失败"}


def query_icp(domain: str, tries: int = 3) -> dict:
    cid = os.environ.get("APIHZ_ID", "88888888")
    key = os.environ.get("APIHZ_KEY", "88888888")
    url = f"{_API}?id={cid}&key={key}&domain={domain}"
    last = ""
    for i in range(1, tries + 1):
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=20) as r:
                return parse_icp(r.read().decode("utf-8", "ignore"))
        except Exception as e:
            last = str(e)
            print(f"[!] ICP 查询第 {i}/{tries} 次失败: {e}")
            if i < tries:
                time.sleep(2 * i)
    return {"filed": False, "msg": f"请求失败: {last}"}


def run_icp(domain: str, out: str) -> dict:
    print(f"[*] ICP 备案查询: {domain}")
    res = query_icp(domain)
    path = os.path.join(out, f"icp_{domain}.json")   # 多域名时互不覆盖
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"domain": domain, **res}, f, ensure_ascii=False, indent=2)
    if res.get("filed"):
        print(f"[+] 备案号: {res['icp']}")
        print(f"    主办单位: {res['unit']}    类型: {res.get('type') or '-'}    审核: {res.get('time') or '-'}")
    else:
        print(f"[!] 未查询到备案信息（{res.get('msg')}）—— 也可能是未备案或接口限频，建议人工复核 beian.miit.gov.cn")
    print(f"    -> {path}")
    return res


if __name__ == "__main__":
    import sys
    run_icp(sys.argv[1], "out")
