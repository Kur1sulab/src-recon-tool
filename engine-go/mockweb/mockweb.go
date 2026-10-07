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

// ── sec 场景（基线检查 secheaders/webfiles 集成测试靶站；独立常量，不参与
// Python parity 漂移守卫——守卫只钉 SPAShell 与 Real，见 mockweb_test.go）──

// SecHomePage sec 场景首页：og meta（property 前/content 前两种属性序）+ 三类链接
// （同站相对 / 子域绝对 / 外部域绝对）。
const SecHomePage = "<!doctype html><html><head><title>Sec Demo</title>" +
	"<meta property=\"og:title\" content=\"Sec 演示站\">" +
	"<meta content=\"https://cdn.secexample.com/og.png\" property=\"og:image\">" +
	"</head><body>" +
	"<a href=\"/about\">关于</a>" +
	"<a href=\"https://portal.secexample.com/login\">门户</a>" +
	"<a href=\"https://third-cdn.example.net/metrics\">第三方</a>" +
	"</body></html>"

// SecSecurityTxt sec 场景 security.txt 样例。
const SecSecurityTxt = "Contact: mailto:security@secexample.com\n" +
	"Encryption: https://secexample.com/key.asc\n" +
	"Policy: https://secexample.com/policy\n" +
	"Preferred-Languages: zh, en\n"

// secBaseURL sec 场景动态内容的站点基址（httptest 为 http）。
func secBaseURL(r *http.Request) string { return "http://" + r.Host }

// secRobots sec 场景 robots.txt（Sitemap 行回指本站，两步取法用例）。
func secRobots(r *http.Request) string {
	return "User-agent: *\nDisallow: /admin\nDisallow: /backup\nAllow: /public\n" +
		"Sitemap: " + secBaseURL(r) + "/sec/sitemap.xml\n"
}

// secSitemap sec 场景 sitemap.xml（两个 loc，基址动态）。
func secSitemap(r *http.Request) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
		"<url><loc>" + secBaseURL(r) + "/sec/page1</loc></url>" +
		"<url><loc>" + secBaseURL(r) + "/sec/page2</loc></url>" +
		"</urlset>"
}

// writeSecSecure sec 场景「安全标杆」响应：8 条安全头全齐 + 规范 Cookie +
// Cloudflare 特征头（WAF 表用例）。
func writeSecSecure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=10886400; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	h.Set("Server", "cloudflare")
	h.Set("CF-Ray", "8abc123-HKG")
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc123", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	send(w, http.StatusOK, "text/html; charset=utf-8",
		"<!doctype html><html><head><title>Secured</title></head><body>ok</body></html>")
}

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
		case "sec": // 基线检查靶站（secheaders/webfiles 集成测试；独立场景，零 parity 依赖）
			switch sub {
			case "/", "":
				send(w, http.StatusOK, "text/html; charset=utf-8", SecHomePage)
			case "/robots.txt":
				send(w, http.StatusOK, "text/plain", secRobots(r))
			case "/sitemap.xml":
				send(w, http.StatusOK, "application/xml", secSitemap(r))
			case "/.well-known/security.txt":
				send(w, http.StatusOK, "text/plain", SecSecurityTxt)
			case "/secure":
				writeSecSecure(w)
			case "/plain": // 无任何安全头的对照组
				send(w, http.StatusOK, "text/html; charset=utf-8",
					"<!doctype html><html><head><title>Plain</title></head><body>plain</body></html>")
			case "/cookie-bad": // 全缺属性的 Cookie（Secure/HttpOnly/SameSite 皆无）
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "xyz", Path: "/"})
				send(w, http.StatusOK, "text/html", "<!doctype html><html><body>cookie</body></html>")
			case "/redirect": // 302 → /sec/secure（逐跳链用例）
				w.Header().Set("Location", "/sec/secure")
				send(w, http.StatusFound, "text/html", "")
			default:
				send(w, http.StatusOK, "text/html; charset=utf-8", SecHomePage)
			}
		default:
			send(w, http.StatusNotFound, "text/html", "<html><body>404</body></html>")
		}
	})
}

// New 启动 httptest 靶站（调用方负责 srv.Close()）。
func New() *httptest.Server {
	return httptest.NewServer(Handler())
}
