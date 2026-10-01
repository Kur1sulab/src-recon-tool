// Package mockweb 用 Go httptest 重建 tests/mock_server.py 的全部语义，
// 供 Go 引擎单测与 Python↔Go parity 测试共打同一个靶站（两引擎各打各的 mock
// 会因响应头差异污染 parity，必须同站）。
// 常量与 Python 侧逐字节一致，mockweb 包的漂移守卫测试负责钉住。
package mockweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
)

// SPAShell 对齐 mock_server.SPA_SHELL（注意 </head> 后有一个真实换行）。
const SPAShell = "<!doctype html><html><head><title>My App</title></head>\n" +
	"<body><div id=\"app\"></div><script src=\"/static/app.js\"></script></body></html>"

// LoginPage 对齐 mock_server.LOGIN_PAGE。
const LoginPage = "<!doctype html><html><head><title>登录</title></head>\n" +
	"<body><form action=\"/login\" method=\"post\"><input name=\"user\"><input name=\"pass\" type=\"password\"></form></body></html>"

// jsintel 场景的假敏感值（与 Python 侧分段拼接结果一致）。
const (
	FakeToken = "InlT" + "0ken99ab"
	FakePw    = "Sup3r" + "S3cret99"
	FakeAppID = "wx" + "1234567890"
)

// JSSitePage 对齐 mock_server.JSSITE_PAGE。
const JSSitePage = "<!doctype html><html><head><title>JS Site</title></head><body>" +
	"<script src=\"/jssite/static/app.js\"></script>" +
	"<script>var cfg={token:'" + FakeToken + "'};fetch('/api/v1/users');</script>" +
	"</body></html>"

// JSSiteAppJS 对齐 mock_server.JSSITE_APPJS（末尾带换行）。
const JSSiteAppJS = "axios.post('/api/v2/login',{user:1});\n" +
	"fetch('https://api.example-cdn.com/v3/pay');\n" +
	"var logo='/static/logo.png';\n" +
	"var css='/assets/main.css';\n" +
	"var cfg2={password:'" + FakePw + "',appId:'" + FakeAppID + "'};\n" +
	"var intranet='http://10.0.0.5:8080/metrics';\n" +
	"var q='/weather/beijing';\n"

// FpPageBody 指纹 parity 场景页：只含「技术特征」（ThinkPHP 报错页特征串），
// 规则可命中但不会误伤自然语言。响应头用受控显式头（Server/X-Powered-By）。
const FpPageBody = "<!doctype html><html><head><title>FP Page</title></head>" +
	"<body><h1>think_exception</h1><p>ThinkPHP V5.1 error trace</p>" +
	"<p>/index.php?s=/module/action</p></body></html>"

// RealEntry 真实暴露条目：Content-Type + Body（字节级照抄 Python REAL 常量）。
type RealEntry struct {
	Ctype string
	Body  string
}

// Real 对齐 mock_server.REAL（键为 /real/ 下的子路径）。
var Real = map[string]RealEntry{
	"/swagger-ui.html": {"text/html", "<html><head><title>Swagger UI</title></head>" +
		"<body><link rel=\"stylesheet\" href=\"swagger-ui.css\"><div id=\"swagger-ui\"></div>" +
		"<script>SwaggerUIBundle({url:'/v3/api-docs'})</script></body></html>"},
	"/v3/api-docs": {"application/json", `{"openapi":"3.0.1","info":{"title":"Demo API"},"paths":{"/user":{"get":{}}}}`},
	"/actuator":    {"application/json", `{"_links":{"self":{"href":"http://x/actuator"},"env":{"href":"http://x/actuator/env"}}}`},
	"/actuator/env": {"application/json", `{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig",` +
		`"properties":{"spring.datasource.password":{"value":"Sup3rS3cret"}}}]}`},
	"/actuator/heapdump": {"application/octet-stream", "JAVA PROFILE 1.0.8" + strings.Repeat("\x00", 4096)},
	"/.env":              {"text/plain", "APP_ENV=production\nDB_PASSWORD=Sup3rS3cret\nAPP_KEY=base64:AAAA\n"},
	"/robots.txt":        {"text/plain", "User-agent: *\nDisallow: /admin\n"},
}

// TruePositives 对齐 mock_server.TRUE_POSITIVES。
var TruePositives = []string{"/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/env",
	"/actuator/heapdump", "/.env", "/robots.txt"}

func send(w http.ResponseWriter, code int, ctype, body string) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// Handler 复刻 mock_server.Handler 的路由语义：第一段路径决定场景。
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.Trim(r.URL.Path, "/")
		parts := strings.Split(clean, "/")
		scenario := parts[0]
		sub := "/"
		if len(parts) > 1 {
			sub = "/" + strings.Join(parts[1:], "/")
		}
		switch scenario {
		case "soft404": // SPA：无论问什么都回同一个 200 HTML 外壳
			send(w, http.StatusOK, "text/html; charset=utf-8", SPAShell)
		case "waf": // 全局 403
			send(w, http.StatusForbidden, "text/html", "<html><body>403 Forbidden by WAF</body></html>")
		case "loginredirect": // 任何路径 302 → /loginredirect/login（重定向环，同 Python）
			w.Header().Set("Location", "/loginredirect/login")
			send(w, http.StatusFound, "text/html", "")
		case "empty": // 标准 404 对照组
			send(w, http.StatusNotFound, "text/html", "<html><body>404</body></html>")
		case "api404": // 自定义 JSON 软 404
			send(w, http.StatusOK, "application/json",
				`{"code":200,"data":{"id":0,"username":null,"email":null},"msg":"ok"}`)
		case "jssite":
			if sub == "/static/app.js" {
				send(w, http.StatusOK, "application/javascript", JSSiteAppJS)
			} else {
				send(w, http.StatusOK, "text/html; charset=utf-8", JSSitePage)
			}
		case "real":
			if e, ok := Real[sub]; ok {
				send(w, http.StatusOK, e.Ctype, e.Body)
			} else {
				send(w, http.StatusNotFound, "text/html", "<html><body>404</body></html>")
			}
		case "fppage": // Go 靶站扩展：受控显式头，供指纹 parity（两引擎打同一站）
			w.Header().Set("Server", "nginx")
			w.Header().Set("X-Powered-By", "PHP/7.4")
			send(w, http.StatusOK, "text/html; charset=utf-8", FpPageBody)
		default:
			send(w, http.StatusNotFound, "text/html", "<html><body>404</body></html>")
		}
	})
}

// New 启动 httptest 靶站（调用方负责 srv.Close()）。
func New() *httptest.Server {
	return httptest.NewServer(Handler())
}
