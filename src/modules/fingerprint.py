# -*- coding: utf-8 -*-
"""指纹识别：内置常用 Web 指纹规则（headers + body 双通道），
输出命中的 CMS/框架/中间件。规则可按 EHole 思路自行扩充。
"""
import json
import os
import re
import ssl
import urllib.request

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"}

RULES = [
    # 注意：body 匹配只认「技术特征」（版本号/报错页/框架专属路径），
    # 不能匹配自然语言里出现的框架名词——否则一篇提到 "ThinkPHP" 的文章
    # 会把整个站点误判为 ThinkPHP（静态博客实测踩过）。
    {"name": "ThinkPHP",  "where": "header", "pattern": r"x-powered-by:\s*thinkphp", "type": "framework"},
    {"name": "ThinkPHP",  "where": "body",   "pattern": r"thinkphp[_\-/ ]?v?\d+\.\d|think_exception|thinkphp_exception|_method=__construct|/index\.php\?s=/", "type": "framework"},
    {"name": "Shiro",     "where": "header", "pattern": r"rememberme=deleteme",  "type": "framework"},
    {"name": "Spring",    "where": "body",   "pattern": r"whitelabel error page", "type": "framework"},
    {"name": "WordPress", "where": "header", "pattern": r"x-powered-by:\s*wordpress|link:.*wp-json", "type": "cms"},
    {"name": "WordPress", "where": "body",   "pattern": r"wp-content/(themes|plugins|uploads)|wp-includes/(js|css)/", "type": "cms"},
    {"name": "Discuz",    "where": "body",   "pattern": r"discuz!|forum\.php\?mod=", "type": "cms"},
    {"name": "Nginx",     "where": "header", "pattern": r"nginx|openresty|tengine", "type": "server"},
    {"name": "Apache",    "where": "header", "pattern": r"apache",               "type": "server"},
    {"name": "IIS",       "where": "header", "pattern": r"microsoft-iis",        "type": "server"},
    {"name": "Vue",       "where": "body",   "pattern": r"data-v-[0-9a-f]{8}|__vue__", "type": "frontend"},
    {"name": "React",     "where": "body",   "pattern": r"data-reactroot|__react", "type": "frontend"},
    # ── 中间件 / 运维面 / API 文档（规则均取「技术特征」，避免正文误伤）──
    {"name": "Spring Boot", "where": "header", "pattern": r"x-application-context", "type": "framework"},
    {"name": "Tomcat",    "where": "header", "pattern": r"apache-coyote|tomcat",  "type": "middleware"},
    {"name": "Jetty",     "where": "header", "pattern": r"jetty",                 "type": "middleware"},
    {"name": "Undertow",  "where": "header", "pattern": r"undertow",              "type": "middleware"},
    {"name": "WebLogic",  "where": "header", "pattern": r"weblogic",              "type": "middleware"},
    {"name": "Jenkins",   "where": "header", "pattern": r"x-jenkins",             "type": "devops"},
    {"name": "Grafana",   "where": "body",   "pattern": r'"grafanabootdata"|grafana-app|window\.grafana', "type": "devops"},
    {"name": "Kibana",    "where": "body",   "pattern": r"kbn-injected-metadata", "type": "devops"},
    {"name": "Elasticsearch", "where": "body", "pattern": r'"you know, for search"|"cluster_name"\s*:', "type": "middleware"},
    {"name": "GitLab",    "where": "body",   "pattern": r'"gitlab_url"|gon\.gitlab|gitlab-ee|gitlab-ce', "type": "devops"},
    {"name": "Jira",      "where": "body",   "pattern": r"ajs-version-number|com-atlassian-jira", "type": "devops"},
    {"name": "phpMyAdmin", "where": "body",  "pattern": r'id="pma_username"|pma_password|name="pma_username"', "type": "tool"},
    {"name": "RabbitMQ",  "where": "body",   "pattern": r"rabbitmq management",   "type": "middleware"},
    {"name": "Harbor",    "where": "body",   "pattern": r'harbor-logo|"harbor_version"', "type": "devops"},
    {"name": "Swagger UI", "where": "body",  "pattern": r"swagger-ui\.css|swagger-ui-bundle", "type": "api"},
    {"name": "Nacos",     "where": "body",   "pattern": r'console-ui|"nacos"',     "type": "middleware"},
]


def run_fingerprint(url: str, out: str):
    hits = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            body = r.read(300000).decode("utf-8", "ignore").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
    except Exception as e:
        print(f"[!] 指纹识别请求失败: {e}")
        body = headers = ""
    for rule in RULES:
        haystack = headers if rule["where"] == "header" else body
        if re.search(rule["pattern"], haystack):
            if any(h["name"] == rule["name"] for h in hits):   # 同一指纹多规则命中只记一次
                continue
            hits.append({"name": rule["name"], "type": rule["type"]})
    path = os.path.join(out, "fingerprint.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(hits, f, ensure_ascii=False, indent=2)
    names = "、".join(h["name"] for h in hits) or "无"
    print(f"[+] 指纹识别完成（{len(hits)} 个命中: {names}）-> {path}")
