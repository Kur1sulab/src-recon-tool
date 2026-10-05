package mockweb

// sec 场景路由验证（基线检查靶站；独立测试，零 parity 依赖——
// 不触碰 TestRealConstantsMatchPythonMock 的守卫范围）。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecScenario(t *testing.T) {
	srv := New()
	defer srv.Close()
	get := func(path string) (*http.Response, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	// 首页：og meta + 三类链接
	if resp, body := get("/sec/"); resp.StatusCode != 200 ||
		!strings.Contains(body, `property="og:title"`) || !strings.Contains(body, "portal.secexample.com") {
		t.Errorf("sec 首页异常: %d %q", resp.StatusCode, body)
	}
	// robots.txt：Disallow 条目 + 绝对 Sitemap 行回指本站
	resp, body := get("/sec/robots.txt")
	if resp.StatusCode != 200 || !strings.Contains(body, "Disallow: /admin") ||
		!strings.Contains(body, "Sitemap: "+srv.URL+"/sec/sitemap.xml") {
		t.Errorf("sec robots 异常: %d %q", resp.StatusCode, body)
	}
	// sitemap.xml：两个 loc
	if _, body := get("/sec/sitemap.xml"); strings.Count(body, "<loc>") != 2 {
		t.Errorf("sec sitemap 应含 2 个 loc: %q", body)
	}
	// security.txt
	if _, body := get("/sec/.well-known/security.txt"); !strings.Contains(body, "Contact: mailto:security@secexample.com") {
		t.Errorf("sec security.txt 异常: %q", body)
	}
	// /sec/secure：8 条安全头 + 规范 Cookie + Cloudflare 特征
	resp, _ = get("/sec/secure")
	h := resp.Header
	for name, want := range map[string]string{
		"Strict-Transport-Security":   "max-age=10886400",
		"Content-Security-Policy":     "default-src 'self'",
		"X-Frame-Options":             "DENY",
		"X-Content-Type-Options":      "nosniff",
		"Referrer-Policy":             "no-referrer",
		"Permissions-Policy":          "geolocation=()",
		"Cross-Origin-Opener-Policy":  "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Server":                      "cloudflare",
		"CF-Ray":                      "8abc123-HKG",
	} {
		if !strings.Contains(h.Get(name), want) {
			t.Errorf("sec secure 头 %s = %q, 应含 %q", name, h.Get(name), want)
		}
	}
	var secureCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "sid" {
			secureCookie = c
		}
	}
	if secureCookie == nil || !secureCookie.Secure || !secureCookie.HttpOnly ||
		secureCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("sec secure Cookie 属性异常: %+v", secureCookie)
	}
	// /sec/plain：无 HSTS 对照组
	if resp, _ = get("/sec/plain"); resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("sec plain 不应带 HSTS")
	}
	// /sec/cookie-bad：无属性 Cookie
	if resp, _ = get("/sec/cookie-bad"); len(resp.Cookies()) != 1 || resp.Cookies()[0].Secure {
		t.Errorf("sec cookie-bad 应为无属性 Cookie: %+v", resp.Cookies())
	}
	// /sec/redirect：302 → /sec/secure
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp2, err := noRedirect.Get(srv.URL + "/sec/redirect")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 302 || resp2.Header.Get("Location") != "/sec/secure" {
		t.Errorf("sec redirect: %d %q", resp2.StatusCode, resp2.Header.Get("Location"))
	}
	// httptest 形态自查（记录在案）
	_ = httptest.NewServer
}
