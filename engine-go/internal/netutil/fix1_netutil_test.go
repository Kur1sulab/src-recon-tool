package netutil

// fix1_netutil_test.go — 第 1 轮审计修复回归（netutil）：
//   1. Fetch error 字段剥离 URL（审计 low#5：query 里的 key 不得进日志/证据包）
//   2. HopCheck 逐跳校验（P1：302 落点不再免检）
//   3. SafeFilename Windows 保留设备名（对抗 P2）

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchErrStripsURL(t *testing.T) {
	r := Fetch("http://127.0.0.1:1/?api_key=TOPSECRET_demo", FetchOpt{Timeout: 2 * time.Second})
	if r.OK {
		t.Fatal("拒绝连接应失败")
	}
	if strings.Contains(r.Err, "api_key") || strings.Contains(r.Err, "http://") {
		t.Fatalf("error 字段泄漏 URL/query: %q", r.Err)
	}
	if r.Err == "" {
		t.Fatal("error 字段应保留原因文本")
	}
}

func TestHopCheckBlocksRedirectTarget(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("TOPSECRET-INNER"))
	}))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outerRedirectTarget(inner.URL), http.StatusFound)
	}))
	defer outer.Close()

	// ① HopCheck 拒绝 → 中止跟随，按失败处理
	blocked := Fetch(outer.URL, FetchOpt{Timeout: 5 * time.Second, Follow: true,
		HopCheck: func(string) error { return errHopBlocked }})
	if blocked.OK || strings.Contains(blocked.Body, "TOPSECRET-INNER") {
		t.Fatalf("HopCheck 拒绝后不得取回落点内容: ok=%v body=%q", blocked.OK, blocked.Body)
	}
	if !strings.Contains(blocked.Err, errHopBlocked.Error()) {
		t.Fatalf("error 应携带拒绝原因: %q", blocked.Err)
	}
	// error 字段同样不得回显完整 URL（errReason 剥前缀）
	if strings.Contains(blocked.Err, "http://") {
		t.Fatalf("error 字段泄漏 URL: %q", blocked.Err)
	}

	// ② HopCheck 放行 → 正常跟随
	ok := Fetch(outer.URL, FetchOpt{Timeout: 5 * time.Second, Follow: true,
		HopCheck: func(string) error { return nil }})
	if !ok.OK || !strings.Contains(ok.Body, "TOPSECRET-INNER") {
		t.Fatalf("HopCheck 放行应取回落点内容: %+v", ok)
	}

	// ③ 不带 HopCheck（默认 nil）保持旧行为：跟随成功（parity 不受影响）
	legacy := Fetch(outer.URL, FetchOpt{Timeout: 5 * time.Second, Follow: true})
	if !legacy.OK || !strings.Contains(legacy.Body, "TOPSECRET-INNER") {
		t.Fatalf("默认无 HopCheck 应保持跟随语义: %+v", legacy)
	}
}

func outerRedirectTarget(innerURL string) string { return innerURL + "/secret" }

var errHopBlocked = errFixed("重定向落点未通过边界校验")

type errFixed string

func (e errFixed) Error() string { return string(e) }

func TestSafeFilenameWindowsReservedStems(t *testing.T) {
	cases := []struct{ in, want string }{
		{"con.txt", "con_.txt"},
		{"CON", "CON_"},
		{"com1.zip", "com1_.zip"},
		{"nul", "nul_"},
		{"LPT9.log", "LPT9_.log"},
		{"aux", "aux_"},
		{"config.txt", "config.txt"},   // 主干非设备名不动
		{"conny.txt", "conny.txt"},     // 前缀命中不算
		{"audit_report.md", "audit_report.md"},
		{"bad/name?.txt", "bad_name_.txt"},
	}
	for _, c := range cases {
		if got := SafeFilename(c.in); got != c.want {
			t.Fatalf("SafeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
