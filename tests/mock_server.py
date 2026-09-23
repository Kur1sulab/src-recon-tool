# -*- coding: utf-8 -*-
"""审计用可控靶站（stdlib，零依赖）：四种典型站点行为，用来打测模块的误报/漏报。

路由（第一段决定场景）:
  /soft404/*      软 404：任何路径都返回 200 + 同一个 HTML 首页（SPA 常见）
  /real/*         真实暴露：swagger / actuator / heapdump / .env 都是真的
  /waf/*          全局 403（WAF 或权限网关的 catch-all）
  /loginredirect/* 任何路径 302 → /login（200 HTML 登录页）
  /empty/*        标准 404（对照组）

用法:
  python tests/mock_server.py [port]      # 默认 8799
"""
import hashlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SPA_SHELL = """<!doctype html><html><head><title>My App</title></head>
<body><div id="app"></div><script src="/static/app.js"></script></body></html>"""

LOGIN_PAGE = """<!doctype html><html><head><title>登录</title></head>
<body><form action="/login" method="post"><input name="user"><input name="pass" type="password"></form></body></html>"""

REAL = {
    "/swagger-ui.html": ("text/html", "<html><head><title>Swagger UI</title></head>"
                                       '<body><link rel="stylesheet" href="swagger-ui.css"><div id="swagger-ui"></div>'
                                       "<script>SwaggerUIBundle({url:'/v3/api-docs'})</script></body></html>"),
    "/v3/api-docs": ("application/json", '{"openapi":"3.0.1","info":{"title":"Demo API"},"paths":{"/user":{"get":{}}}}'),
    "/actuator": ("application/json", '{"_links":{"self":{"href":"http://x/actuator"},"env":{"href":"http://x/actuator/env"}}}'),
    "/actuator/env": ("application/json", '{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig",'
                                           '"properties":{"spring.datasource.password":{"value":"Sup3rS3cret"}}}]}'),
    "/actuator/heapdump": ("application/octet-stream", "JAVA PROFILE 1.0.8" + "\x00" * 4096),
    "/.env": ("text/plain", "APP_ENV=production\nDB_PASSWORD=Sup3rS3cret\nAPP_KEY=base64:AAAA\n"),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\n"),
}
TRUE_POSITIVES = ["/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/env",
                  "/actuator/heapdump", "/.env", "/robots.txt"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"      # 短连接：避免测试进程里遗留 keep-alive 套接字

    def _send(self, code, ctype, body, extra=None):
        raw = body.encode("utf-8", "ignore") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except Exception:
            pass

    def do_GET(self):
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        scenario = parts[0] if parts else ""
        sub = "/" + "/".join(parts[1:]) if len(parts) > 1 else "/"

        if scenario == "soft404":
            # SPA：无论问什么都回同一个 200 HTML 外壳（典型误报陷阱）
            return self._send(200, "text/html; charset=utf-8", SPA_SHELL)
        if scenario == "waf":
            return self._send(403, "text/html", "<html><body>403 Forbidden by WAF</body></html>")
        if scenario == "loginredirect":
            return self._send(302, "text/html", "", {"Location": "/loginredirect/login"})
        if scenario == "empty":
            return self._send(404, "text/html", "<html><body>404</body></html>")
        if scenario == "api404":
            # 自定义 JSON 软 404：任何路径都回 200 + 泛化 JSON（含 id/username 等常见键）
            body = '{"code":200,"data":{"id":0,"username":null,"email":null},"msg":"ok"}'
            return self._send(200, "application/json", body)
        if scenario == "real":
            if sub in REAL:
                ctype, body = REAL[sub]
                return self._send(200, ctype, body)
            return self._send(404, "text/html", "<html><body>404</body></html>")
        return self._send(404, "text/html", "<html><body>404</body></html>")

    def log_message(self, *a):        # 静音
        pass


def serve(port=8799):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    srv = serve(p)
    print(f"mock server on http://127.0.0.1:{p}  场景: soft404 / real / waf / loginredirect / empty")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
