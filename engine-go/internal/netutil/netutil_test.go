package netutil

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/parity"
)

// ── fetch ──

func TestFetchBasicFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()
	r := Fetch(srv.URL+"/hello", FetchOpt{Follow: true})
	if !r.OK || r.Status != 200 {
		t.Fatalf("ok/status = %v/%d", r.OK, r.Status)
	}
	if r.Size != 11 || r.Body != "hello world" {
		t.Fatalf("size/body = %d/%q", r.Size, r.Body)
	}
	want := fmt.Sprintf("%x", sha1.Sum([]byte("hello world")))[:16]
	if r.SHA1 != want {
		t.Fatalf("sha1 = %q, want %q", r.SHA1, want)
	}
	if r.Ctype != "text/plain" {
		t.Fatalf("ctype = %q", r.Ctype)
	}
	if r.Headers["content-type"] != "text/plain" {
		t.Fatalf("headers 小写键缺失: %v", r.Headers)
	}
	if r.FinalURL != srv.URL+"/hello" {
		t.Fatalf("final_url = %q", r.FinalURL)
	}
}

func TestFetch4xx5xxStillOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	r := Fetch(srv.URL+"/x", FetchOpt{Follow: true})
	if !r.OK || r.Status != 403 {
		t.Fatalf("4xx/5xx 应算 ok=true（Python HTTPError 分支），got %v/%d", r.OK, r.Status)
	}
	if !strings.Contains(r.Body, "nope") {
		t.Fatalf("错误响应体应可读: %q", r.Body)
	}
}

func TestFetchSchemeWhitelist(t *testing.T) {
	for _, u := range []string{"file:///C:/Windows/win.ini", "ftp://example.com/x", "not a url"} {
		r := Fetch(u, FetchOpt{})
		if r.OK || r.Err == "" {
			t.Fatalf("%q 应被协议白名单拦下, got ok=%v err=%q", u, r.OK, r.Err)
		}
	}
}

func TestFetchDefaultUA(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()
	_ = Fetch(srv.URL, FetchOpt{})
	if got != DefaultUA {
		t.Fatalf("UA = %q, want %q", got, DefaultUA)
	}
}

func TestFetchTruncateThenHash(t *testing.T) {
	body := strings.Repeat("A", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	r := Fetch(srv.URL, FetchOpt{MaxBytes: 10})
	if r.Size != 10 {
		t.Fatalf("截断后 size = %d", r.Size)
	}
	want := fmt.Sprintf("%x", sha1.Sum([]byte(body[:10])))[:16] // 先截断后哈希
	if r.SHA1 != want {
		t.Fatalf("sha1 = %q, want %q（必须对截断后的 raw 计算）", r.SHA1, want)
	}
}

func TestFetchHeaderLowercaseLastWins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("X-Test", "first")
		w.Header().Add("X-Test", "second")
	}))
	defer srv.Close()
	r := Fetch(srv.URL, FetchOpt{})
	if r.Headers["x-test"] != "second" {
		t.Fatalf("同键多值应后写覆盖（Python dict 推导语义）: %q", r.Headers["x-test"])
	}
}

func TestFetchRedirectLoopPythonSemantics(t *testing.T) {
	// 重定向环：Python 侧 urllib 超限抛 HTTPError(302) → ok=true status=302，
	// 空体的摘要为 da39a3ee5e6b4b0d（非空字符串）→ baseline 判 redirect。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	r := Fetch(srv.URL+"/start", FetchOpt{Follow: true})
	if !r.OK || r.Status != 302 {
		t.Fatalf("重定向超限应返回最后一个 302（ok=true），got %v/%d err=%q", r.OK, r.Status, r.Err)
	}
	if r.SHA1 != "da39a3ee5e6b4b0d" {
		t.Fatalf("空体摘要 = %q", r.SHA1)
	}
	if !strings.HasSuffix(r.FinalURL, "/next") {
		t.Fatalf("final_url = %q（应停在最后一次请求的 URL）", r.FinalURL)
	}
}

func TestFetchNoFollowReturns3xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/target")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	r := Fetch(srv.URL+"/origin", FetchOpt{Follow: false})
	if !r.OK || r.Status != 302 || r.FinalURL != srv.URL+"/origin" {
		t.Fatalf("不跟随应返回 302 本身: %v/%d/%q", r.OK, r.Status, r.FinalURL)
	}
}

func TestFetchErrTruncated(t *testing.T) {
	r := Fetch("http://127.0.0.1:1/", FetchOpt{Timeout: 2 * time.Second})
	if r.OK {
		t.Fatal("连不上的端口不应 ok")
	}
	if len([]rune(r.Err)) > 120 {
		t.Fatalf("Err 应截 120 字符，got %d", len([]rune(r.Err)))
	}
}

// ── urlcheck ──

func TestCheckHTTPURLRules(t *testing.T) {
	if u, err := CheckHTTPURL("http://8.8.8.8/x", false); err != nil || u != "http://8.8.8.8/x" {
		t.Fatalf("公网 IP 字面量应放行: %q %v", u, err)
	}
	for _, bad := range []string{"ftp://8.8.8.8/", "http:///path", "not a url"} {
		if _, err := CheckHTTPURL(bad, false); err == nil {
			t.Fatalf("%q 应报错", bad)
		}
	}
	// 私网/保留段（含 Clash fake-ip 段 198.18.0.0/15）：默认阻断
	for _, host := range []string{"198.18.0.1", "127.0.0.1", "10.1.2.3", "192.0.2.5", "240.1.1.1", "203.0.113.7"} {
		if _, err := CheckHTTPURL("http://"+host+"/", false); err == nil {
			t.Fatalf("%s 默认应阻断（Python is_private 全集）", host)
		}
		if _, err := CheckHTTPURL("http://"+host+"/", true); err != nil {
			t.Fatalf("%s allowPrivate=true 应放行: %v", host, err)
		}
	}
}

// TestIPBlockedMatchesPython 动态 python 探针：逐 IP 对照 Python 3.8 ipaddress
// 的 is_private/is_loopback/is_link_local/is_reserved 联合判定，钉死全集语义。
func TestIPBlockedMatchesPython(t *testing.T) {
	ips := []string{
		"0.0.0.0", "10.0.0.1", "127.0.0.1", "169.254.1.1", "172.16.5.5",
		"192.0.0.1", "192.0.0.8", "192.0.0.170", "192.0.2.1", "192.168.1.1",
		"198.18.0.1", "198.51.100.7", "203.0.113.9", "240.0.0.1",
		"255.255.255.255", "8.8.8.8", "1.2.3.4", "100.64.0.1",
		"::1", "::", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "fd00::1",
		"2001:db8::1", "2001:2::75", "100::1", "101::1", "ff00::1",
		"2002::1", "2606:4700::1111",
	}
	args := append([]string{`
import ipaddress, json, sys
out = {}
for s in sys.argv[1:]:
    try:
        ip = ipaddress.ip_address(s)
        out[s] = bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        out[s] = None
print(json.dumps(out))
`}, ips...)
	out := parity.RunPy(t, args[0], args[1:]...)
	var py map[string]bool
	t.Helper()
	if err := jsonUnmarshalInto(out, &py); err != nil {
		t.Fatalf("python 探针输出解析失败: %v\n%s", err, out)
	}
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("Go 解析 %s 失败: %v", s, err)
		}
		got := ipBlocked(a)
		want, ok := py[s]
		if !ok {
			t.Fatalf("python 侧无法解析 %s（探针表需修正）", s)
		}
		if got != want {
			t.Errorf("ip %s: Go blocked=%v, Python=%v —— 私网全集表与 Python 分叉", s, got, want)
		}
	}
}

func jsonUnmarshalInto(s string, v any) error {
	return json.Unmarshal([]byte(s), v)
}

// ── safeio ──

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"a/b:c*d?.txt":     "a_b_c_d_.txt",
		// 期望值以 python re.sub(...)[:64].strip('.') 实测为准（strip 会剥掉开头 ..）
		"../../etc/passwd": "_.._etc_passwd",
		"":                 "unknown",
		".":                "unknown",
		"...":              "unknown",
		"正常.txt":            "__.txt",
	}
	for in, want := range cases {
		if got := SafeFilename(in); got != want {
			t.Errorf("SafeFilename(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SafeFilename(strings.Repeat("a", 100)); len(got) != 64 {
		t.Errorf("截 64 失败: %d", len(got))
	}
}

func TestSafeOutdir(t *testing.T) {
	// Python: safe_outdir("") → "out"（空串先归 "out" 再清洗），不是 out/unknown
	if got := SafeOutdir(""); filepath.ToSlash(got) != "out" {
		t.Errorf("空串应回 out: %q", got)
	}
	// parts 全空（剔除 .. 后无组件）才回 out/unknown
	if got := SafeOutdir(".."); filepath.ToSlash(got) != filepath.ToSlash(filepath.Join("out", "unknown")) {
		t.Errorf("纯 .. 应回 out/unknown: %q", got)
	}
	if got := filepath.ToSlash(SafeOutdir("../x")); strings.Contains(got, "..") {
		t.Errorf(".. 组件应被剔除: %q", got)
	}
	if got := filepath.ToSlash(SafeOutdir("a/../../b")); got != "a/b" {
		t.Errorf("a/../../b 应清洗为 a/b: %q", got)
	}
	if got := filepath.ToSlash(SafeOutdir("out//sub/")); !strings.HasSuffix(got, "out/sub") {
		t.Errorf("多斜杠应规范化: %q", got)
	}
}

func TestSafeWriteRoundTrip(t *testing.T) {
	out := t.TempDir()
	p, err := SafeWrite(out, "subdomains.txt", "a\nb\n")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("应返回绝对路径: %q", p)
	}
	if filepath.Base(p) != "subdomains.txt" {
		t.Fatalf("文件名被意外改写: %q", p)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "a\nb\n" {
		t.Fatalf("内容不一致: %q", b)
	}
	for _, bad := range []string{"../evil", "sub/dir.txt", ""} {
		if _, err := SafeWrite(out, bad, "x"); err == nil {
			t.Errorf("非法文件名 %q 应报错", bad)
		}
	}
}

func TestSafeSubdir(t *testing.T) {
	out := t.TempDir()
	d, err := SafeSubdir(out, "evidence", "a/b")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		t.Fatalf("子目录未创建: %q", d)
	}
	if !strings.Contains(filepath.ToSlash(d), "evidence/a_b") {
		t.Fatalf("每一级都应过白名单: %q", d)
	}
}

// ── baseline / verify_live ──

func TestSameShape(t *testing.T) {
	a := Result{Status: 200, SHA1: "abc", Size: 10, Ctype: "text/html"}
	if !SameShape(a, Result{Status: 200, SHA1: "abc", Size: 99, Ctype: "x"}) {
		t.Error("指纹相等应判同形")
	}
	if !SameShape(a, Result{Status: 200, Size: 10, Ctype: "text/html"}) {
		t.Error("长度+类型相等应判同形")
	}
	if SameShape(a, Result{Status: 200, SHA1: "zzz", Size: 10, Ctype: "other"}) {
		t.Error("类型不同不应判同形")
	}
	if SameShape(a, Result{Status: 404, SHA1: "abc", Size: 10, Ctype: "text/html"}) {
		t.Error("状态码不同不应判同形")
	}
	if SameShape(Result{Status: 200, Size: 0}, Result{Status: 200, Size: 0}) {
		t.Error("size=0 不应判同形（Python bool(0) 语义）")
	}
}

func soft404Server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>same shell</html>"))
	}))
}

func TestBaselineKinds(t *testing.T) {
	srv := soft404Server(t)
	defer srv.Close()
	b := Baseline(srv.URL, 3*time.Second)
	if b.Kind != "soft404" || b.Status != 200 || b.Samples != 2 {
		t.Fatalf("soft404 站基线 = %+v", b)
	}
	if IsBaseline(Result{Status: 200, SHA1: b.SHA1, Size: b.Size, Ctype: b.Ctype, URL: srv.URL + "/x", FinalURL: srv.URL + "/x"}, b) != true {
		t.Error("同形 200 响应应判为基线（catch-all）")
	}

	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer waf.Close()
	if b := Baseline(waf.URL, 3*time.Second); b.Kind != "uniform403" {
		t.Fatalf("403 站基线 kind = %s", b.Kind)
	}

	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	}))
	defer loop.Close()
	lb := Baseline(loop.URL, 3*time.Second)
	if lb.Kind != "redirect" {
		t.Fatalf("重定向环基线 kind = %s（Python 实测 redirect）", lb.Kind)
	}
	if lb.Status != 302 {
		t.Fatalf("重定向环基线 status = %d", lb.Status)
	}

	// 站点不可达 → unknown
	b = Baseline("http://127.0.0.1:1/", 1*time.Second)
	if b.Kind != "unknown" {
		t.Fatalf("不可达基线 kind = %s", b.Kind)
	}
}

func TestIsBaselineRedirect(t *testing.T) {
	base := BaselineResult{Kind: "redirect", Status: 302}
	resp := Result{URL: "http://x/a", FinalURL: "http://x/login"}
	if !IsBaseline(resp, base) {
		t.Error("被统一重定向走应判为基线")
	}
	if IsBaseline(Result{URL: "http://x/a", FinalURL: "http://x/a"}, base) {
		t.Error("未被重定向不应判为基线")
	}
	if IsBaseline(Result{}, BaselineResult{Kind: "normal"}) {
		t.Error("normal 基线不应参与判定")
	}
}

func TestVerifyLive(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		_, _ = w.Write([]byte("stable content flag"))
	}))
	defer srv.Close()
	lr := VerifyLive(srv.URL, 2, 3*time.Second, "flag")
	if !lr.Live {
		t.Fatalf("稳定站应 live: %+v", lr)
	}
	if len(lr.Attempts) != 2 {
		t.Fatalf("attempts = %d", len(lr.Attempts))
	}

	flip := 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flip++
		if flip == 1 {
			_, _ = w.Write([]byte("with flag"))
		} else {
			_, _ = w.Write([]byte("gone"))
		}
	}))
	defer srv2.Close()
	if lr := VerifyLive(srv2.URL, 2, 3*time.Second, "flag"); lr.Live {
		t.Fatalf("特征消失应判死: %+v", lr)
	}
}
