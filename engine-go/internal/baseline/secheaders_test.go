package baseline

// secheaders_test.go — 安全响应头检查（§5.1）：
//   验收 2：表驱动单测 8 条规则正/反样例；HSTS max-age 边界（10886399 不达标）。
//   验收 3：mockweb 本地靶站集成：HSTS+Cookie 注入后字段齐全；无 HSTS 判未启用。
//   验收 4：重定向逐跳可见；私网落点被 HopPolicy 拒绝。
//   验收 5：WAF 表用 Cloudflare 样例头命中。
// 全部离线（mockweb=127.0.0.1；打桩传输层）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/mockweb"
)

func headerRowsByName(rows []secHeaderRow) map[string]secHeaderRow {
	m := map[string]secHeaderRow{}
	for _, r := range rows {
		m[r.Name] = r
	}
	return m
}

// TestSecRulesTable 验收 2：8 条规则正/反样例判定一致。
func TestSecRulesTable(t *testing.T) {
	if len(secRules) != 8 {
		t.Fatalf("首版应 8 条规则, 得 %d", len(secRules))
	}
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=10886400; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	rows := headerRowsByName(judgeHeaders(h))
	if len(rows) != 8 {
		t.Fatalf("应判定 8 条, 得 %d", len(rows))
	}
	for name, r := range rows {
		if r.State != "ok" {
			t.Errorf("标杆头 %s 应 ok, 得 %s（%s）", name, r.State, r.Note)
		}
	}
}

func TestSecRulesBadValues(t *testing.T) {
	cases := []struct {
		name, value, wantState, noteContains string
	}{
		{"Strict-Transport-Security", "max-age=31536000", "warn", "includeSubDomains"},
		{"Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'", "warn", "unsafe-inline"},
		{"X-Frame-Options", "ALLOW-FROM http://x", "warn", ""},
		{"X-Content-Type-Options", "textnosniff", "warn", ""},
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set(c.name, c.value)
		row := headerRowsByName(judgeHeaders(h))[c.name]
		if row.State != c.wantState {
			t.Errorf("%s=%q state=%s, want %s", c.name, c.value, row.State, c.wantState)
		}
		if c.noteContains != "" && !strings.Contains(row.Note, c.noteContains) {
			t.Errorf("%s=%q note=%q 应含 %q", c.name, c.value, row.Note, c.noteContains)
		}
	}
}

func TestSecRulesAbsent(t *testing.T) {
	rows := headerRowsByName(judgeHeaders(http.Header{}))
	for name, r := range rows {
		if r.State != "missing" || r.Note == "" {
			t.Errorf("空响应头时 %s 应 missing 且有缺席结论: %+v", name, r)
		}
	}
}

// TestHSTSBoundary 验收 2：10886399 判不达标（MIN_MAX_AGE=10886400，即
// webcheck hsts.js 的 preload 最低线）。
func TestHSTSBoundary(t *testing.T) {
	below := headerRowsByName(judgeHeaders(map[string][]string{
		"Strict-Transport-Security": {"max-age=10886399; includeSubDomains; preload"},
	}))["Strict-Transport-Security"]
	if below.State != "warn" || !strings.Contains(below.Note, "10886400") {
		t.Errorf("10886399 应 warn 且提示阈值: %+v", below)
	}
	at := headerRowsByName(judgeHeaders(map[string][]string{
		"Strict-Transport-Security": {"max-age=10886400; includeSubDomains; preload"},
	}))["Strict-Transport-Security"]
	if at.State != "ok" {
		t.Errorf("10886400 应 ok: %+v", at)
	}
}

// TestSecCookies Cookie 属性审计：任一缺失记不安全项。
func TestSecCookies(t *testing.T) {
	good := &http.Cookie{Name: "sid", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	rows := judgeCookies([]*http.Cookie{good})
	if len(rows[0].Issues) != 0 {
		t.Errorf("规范 Cookie 不应报 issue: %+v", rows[0])
	}
	bad := &http.Cookie{Name: "track", Domain: "example.test", Path: "/"}
	rows = judgeCookies([]*http.Cookie{bad})
	if len(rows[0].Issues) != 3 {
		t.Errorf("全缺属性应 3 项 issue: %+v", rows[0])
	}
}

// TestWAFSignatures 验收 5：Cloudflare 样例头（server: cloudflare / cf-ray）命中；
// 双特征去重只报一家。
func TestWAFSignatures(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("CF-Ray", "8abc-HKG")
	vendors := matchWAF(h)
	if len(vendors) != 1 || vendors[0] != "Cloudflare" {
		t.Errorf("WAF 应命中 Cloudflare 且去重, 得 %v", vendors)
	}
	// 存在即命中型（contains 空）
	h2 := http.Header{}
	h2.Set("X-Sucuri-ID", "123")
	if v := matchWAF(h2); len(v) != 1 || v[0] != "Sucuri" {
		t.Errorf("X-Sucuri-ID 应命中 Sucuri, 得 %v", v)
	}
	if v := matchWAF(http.Header{}); len(v) != 0 {
		t.Errorf("空头不应命中, 得 %v", v)
	}
}

// TestSecHeadersMockweb 验收 3+4：本地靶站集成（127.0.0.1，零外联）。
func TestSecHeadersMockweb(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	o := Options{Domain: "secexample.com", URL: srv.URL + "/sec/secure", AllowPrivate: true, Logf: quietLogf}
	res := RunSecHeaders(o)
	if res.Error != "" {
		t.Fatalf("标杆站不应报错: %s", res.Error)
	}
	// 字段齐全：8 头全 ok / Cookie 无 issue / WAF 命中
	rows := map[string]map[string]any{}
	for _, r := range res.Data["headers"].([]secHeaderRow) {
		rows[r.Name] = map[string]any{"state": r.State, "note": r.Note}
	}
	for _, name := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
		"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy"} {
		if rows[name]["state"] != "ok" {
			t.Errorf("%s 应 ok: %v", name, rows[name])
		}
	}
	if res.Data["missing_count"] != 0 {
		t.Errorf("missing_count = %v", res.Data["missing_count"])
	}
	if n := res.Data["insecure_cookies"]; n != 0 {
		t.Errorf("标杆 Cookie 不应不安全: %v", n)
	}
	wafOK := false
	for _, r := range res.Risks {
		if strings.Contains(r.Title, "Cloudflare") {
			wafOK = true
		}
	}
	if !wafOK {
		t.Errorf("应报 WAF 疑似 Cloudflare: %+v", res.Risks)
	}

	// 无 HSTS 靶 → 判「未启用」（missing）
	o.URL = srv.URL + "/sec/plain"
	res = RunSecHeaders(o)
	if res.Error != "" {
		t.Fatalf("plain 靶不应报错: %s", res.Error)
	}
	if res.Data["missing_count"] == 0 {
		t.Error("plain 靶应缺失安全头")
	}
	found := false
	for _, r := range res.Data["headers"].([]secHeaderRow) {
		if r.Name == "Strict-Transport-Security" {
			found = r.State == "missing" && strings.Contains(r.Note, "未启用")
		}
	}
	if !found {
		t.Error("plain 靶 HSTS 应判未启用")
	}

	// 全缺 Cookie 靶 → 3 项 issue
	o.URL = srv.URL + "/sec/cookie-bad"
	res = RunSecHeaders(o)
	if res.Data["insecure_cookies"] != 1 {
		t.Errorf("cookie-bad 应 1 条不安全 Cookie: %v", res.Data["insecure_cookies"])
	}

	// 重定向链逐跳可见：/sec/redirect → /sec/secure
	o.URL = srv.URL + "/sec/redirect"
	res = RunSecHeaders(o)
	hops := res.Data["hops"].([]secHop)
	if len(hops) != 2 || hops[0].Status != 302 || hops[0].Location != "/sec/secure" {
		t.Errorf("跳转链应逐跳可见: %+v", hops)
	}
	if !strings.HasSuffix(hops[1].URL, "/sec/secure") || hops[1].Status != 200 {
		t.Errorf("第二跳应为 200 终响应: %+v", hops[1])
	}
}

// 打桩传输层： canned 响应序列，记录被请求的 URL（私网落点验证用）。
type stubTransport struct {
	resps    []*http.Response
	visited  []string
	servedN  int
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.visited = append(s.visited, req.URL.String())
	if s.servedN >= len(s.resps) {
		return nil, http.ErrHandlerTimeout
	}
	r := s.resps[s.servedN]
	s.servedN++
	return r, nil
}

func textResp(status int, header http.Header) *http.Response {
	return &http.Response{StatusCode: status, Header: header, Body: http.NoBody, Request: &http.Request{}}
}

// TestSecHeadersPrivateRedirectBlocked 验收 4：公网入口的 302 落到私网 →
// HopPolicy 拒绝、链中止、不向私网发任何请求。
func TestSecHeadersPrivateRedirectBlocked(t *testing.T) {
	stub := &stubTransport{resps: []*http.Response{
		textResp(302, http.Header{"Location": []string{"http://10.0.0.1/next"}}),
	}}
	oldRT, oldHop := secTransport, hopPolicyFor
	secTransport = stub
	hopPolicyFor = func(string) func(string) error { // 模拟公网入口策略：拒私网
		return func(next string) error {
			if strings.HasPrefix(next, "http://10.") {
				return errPrivateHop
			}
			return nil
		}
	}
	t.Cleanup(func() { secTransport, hopPolicyFor = oldRT, oldHop })

	// 入口用 127.0.0.1 字面量 + AllowPrivate（IP 字面量在 CheckHTTPURL 免 DNS，
	// 单测零网络；跳校验由上面的打桩工厂接管）
	res := RunSecHeaders(Options{Domain: "example.test", URL: "http://127.0.0.1:1/", AllowPrivate: true, Logf: quietLogf})
	if res.Data["hops"] == nil {
		t.Fatalf("hops 应在场: %+v", res.Data)
	}
	hops := res.Data["hops"].([]secHop)
	if len(hops) != 1 || !hops[0].Blocked {
		t.Fatalf("落点应被拒并标记 blocked: %+v", hops)
	}
	if res.Error == "" {
		t.Error("未取得终响应应记 error（失败态）")
	}
	for _, u := range stub.visited {
		if strings.HasPrefix(u, "http://10.") {
			t.Errorf("私网落点不应发起请求: %s（visited=%v）", u, stub.visited)
		}
	}
}

// httptest 引用保持（本文件依赖其生态；实际靶站为 mockweb）。
var _ = httptest.NewServer
