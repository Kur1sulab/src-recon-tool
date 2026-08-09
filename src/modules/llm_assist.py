# -*- coding: utf-8 -*-
"""LLM 辅助：汇总 out/ 下的收集结果，做资产分级与攻击面提示。
OpenAI 兼容 API，环境变量:
  LLM_API_KEY   (必需，无 key 自动降级跳过)
  LLM_BASE_URL  (默认 https://api.deepseek.com/v1)
  LLM_MODEL     (默认 deepseek-chat)
输出 out/llm_summary.md
"""
import json
import os
import urllib.request


def _load(out: str, name: str) -> str:
    path = os.path.join(out, name)
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.read()[:4000]


def run_llm(out: str):
    api_key = os.environ.get("LLM_API_KEY", "")
    if not api_key:
        print("[!] 未设置 LLM_API_KEY，跳过 LLM 辅助分析（主流程不受影响）")
        return
    base = os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1")
    model = os.environ.get("LLM_MODEL", "deepseek-chat")

    material = (
        "子域:\n" + _load(out, "subdomains.txt") +
        "\n资产:\n" + _load(out, "assets.txt") +
        "\n指纹:\n" + _load(out, "fingerprint.json") +
        "\n敏感路径:\n" + _load(out, "paths.json")
    )
    prompt = (
        "你是授权 SRC 安全测试的资产分析助手。以下是信息收集结果，请输出:\n"
        "1) 资产分级表（高/中/低价值 + 理由）\n"
        "2) 优先攻击面提示（仅授权测试视角）\n"
        "3) 建议的下一步验证动作\n\n" + material
    )
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }).encode()
    req = urllib.request.Request(
        f"{base.rstrip('/')}/chat/completions", data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.load(r)
        summary = data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[!] LLM 请求失败: {e}")
        return
    path = os.path.join(out, "llm_summary.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(summary)
    print(f"[+] LLM 辅助分析完成 -> {path}")
