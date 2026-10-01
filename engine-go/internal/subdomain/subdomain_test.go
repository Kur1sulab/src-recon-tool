package subdomain

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// withStubs 集中管理包级注入点的保存/恢复（测试串行，无并行竞争）。
// checkBoundary 一并注入放行：测试桩打在 127.0.0.1 httptest 上，而生产
// checkBoundary（= CheckHTTPURL allowPrivate=false）会拦私网——Python 侧测试
// 因 monkeypatch fetch 不触碰真实边界校验，这里等价隔离。
func withStubs(t *testing.T, fn func()) {
	t.Helper()
	oldSleep, oldFind, oldRun := retrySleep, SubfinderFind, SubfinderRun
	oldCrt, oldCs := CrtShURL, CertspotterURL
	oldChk := checkBoundary
	defer func() {
		retrySleep, SubfinderFind, SubfinderRun = oldSleep, oldFind, oldRun
		CrtShURL, CertspotterURL = oldCrt, oldCs
		checkBoundary = oldChk
	}()
	retrySleep = func(time.Duration) {} // 测试免退避等待
	checkBoundary = func(u string) (string, error) { return u, nil }
	fn()
}

// TestChannelBoundaryCheckDegradation（fix1 low#7）：生产 checkBoundary
// （CheckHTTPURL allowPrivate=false）对私网桩 URL 拦截时——
//   - FromCrtSh：0 次重试（不碰 retrySleep）打印「crt.sh 异常」返回空，
//     对齐 Python check_http_url 抛 ValueError → run_subdomain 捕获降级；
//   - FromCertspotter：原样返回 error。
func TestChannelBoundaryCheckDegradation(t *testing.T) {
	oldCrt, oldCs := CrtShURL, CertspotterURL
	defer func() { CrtShURL, CertspotterURL = oldCrt, oldCs }()
	srv := crtShStub(t, crtShFixture, 0)
	defer srv.Close()
	CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
	CertspotterURL = srv.URL + "/?domain=%s&include_subdomains=true&expand=dns_names"

	sleeps := 0
	oldSleep := retrySleep
	retrySleep = func(time.Duration) { sleeps++ }
	defer func() { retrySleep = oldSleep }()

	if got := FromCrtSh("stub.example.com", 3); got != nil {
		t.Fatalf("边界拦截应返回空: %v", got)
	}
	if sleeps != 0 {
		t.Fatalf("边界拦截应 0 次重试（对齐 Python 异常降级）, 实际 sleep %d 次", sleeps)
	}
	if _, err := FromCertspotter("stub.example.com"); err == nil {
		t.Fatal("边界拦截应返回 error")
	}
}

// TestCollectNamesStripsControlChars（fix1 对抗 INFO）：crt.sh 数据内嵌
// \x01\x02 控制字符，清洗后再做后缀过滤与去重。
func TestCollectNamesStripsControlChars(t *testing.T) {
	got := collectNames(2, func(i int) []string {
		if i == 0 {
			return []string{"\x01\x02ctl.stub.example.com", "ok.stub.example.com"}
		}
		return []string{"OK.stub.example.com"} // 大小写去重
	}, "stub.example.com")
	want := []string{"ctl.stub.example.com", "ok.stub.example.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("collectNames = %q, want %q", got, want)
	}
}

func crtShStub(t *testing.T, body string, failFirst int) *httptest.Server {
	t.Helper()
	n := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		if n <= failFirst {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

const crtShFixture = `[{"name_value":"*.stub.example.com\nWWW.stub.example.com\nzz.other.test"},
{"name_value":"api.stub.example.com"}]`

func TestFromCrtShStub(t *testing.T) {
	withStubs(t, func() {
		srv := crtShStub(t, crtShFixture, 0)
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		got := FromCrtSh("stub.example.com", 3)
		want := []string{"api.stub.example.com", "stub.example.com", "www.stub.example.com"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("FromCrtSh = %v, want %v（lstrip *. / lower / endswith / sorted）", got, want)
		}
	})
}

func TestFromCrtShRetryThenSuccess(t *testing.T) {
	withStubs(t, func() {
		srv := crtShStub(t, crtShFixture, 2) // 前两次 502，第三次成功
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		got := FromCrtSh("stub.example.com", 3)
		if len(got) != 3 {
			t.Fatalf("退避重试后应成功: %v", got)
		}
	})
}

func TestFromCrtShAllFail(t *testing.T) {
	withStubs(t, func() {
		srv := crtShStub(t, crtShFixture, 99)
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		if got := FromCrtSh("stub.example.com", 3); got != nil {
			t.Fatalf("重试均失败应优雅返回空: %v", got)
		}
	})
}

func TestFromCertspotterStub(t *testing.T) {
	withStubs(t, func() {
		srv := crtShStub(t, `[{"dns_names":["*.cs2.example","mail.cs2.example"]}]`, 0)
		defer srv.Close()
		CertspotterURL = srv.URL + "/?domain=%s&include_subdomains=true&expand=dns_names"
		got, err := FromCertspotter("cs2.example")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"cs2.example", "mail.cs2.example"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("FromCertspotter = %v, want %v", got, want)
		}
		// 失败路径返回 error（对齐 Python RuntimeError）
		srv2 := crtShStub(t, "boom", 99)
		defer srv2.Close()
		CertspotterURL = srv2.URL + "/?domain=%s"
		if _, err := FromCertspotter("cs2.example"); err == nil {
			t.Fatal("失败应返回 error")
		}
	})
}

// TestRunFallbackChainWithSubfinderAbsent ⑦：subfinder 缺席 → 降级链不受影响。
func TestRunFallbackChainWithSubfinderAbsent(t *testing.T) {
	withStubs(t, func() {
		t.Setenv("ONEFORALL_HOME", "")
		SubfinderFind = func() string { return "" } // 模拟缺席
		srv := crtShStub(t, crtShFixture, 0)
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		out := t.TempDir()
		got := Run("stub.example.com", out)
		if len(got) != 3 {
			t.Fatalf("降级链结果 = %v", got)
		}
		b, err := os.ReadFile(filepath.Join(out, "subdomains.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := parityStripCR(string(b)); got != strings.Join([]string{
			"api.stub.example.com", "stub.example.com", "www.stub.example.com"}, "\n")+"\n" {
			t.Fatalf("subdomains.txt 内容 = %q", got)
		}
	})
}

// TestRunSubfinderFailureNotFatal：subfinder 通道失败只告警，不阻断。
func TestRunSubfinderFailureNotFatal(t *testing.T) {
	withStubs(t, func() {
		t.Setenv("ONEFORALL_HOME", "")
		SubfinderFind = func() string { return "/nonexistent/subfinder.exe" }
		SubfinderRun = func(string, string) ([]string, error) { return nil, os.ErrPermission }
		srv := crtShStub(t, crtShFixture, 0)
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		if got := Run("stub.example.com", t.TempDir()); len(got) != 3 {
			t.Fatalf("subfinder 失败不应影响主链: %v", got)
		}
	})
}

// TestRunSubfinderMergedSorted：subfinder 结果合并进主列表并整体排序。
func TestRunSubfinderMergedSorted(t *testing.T) {
	withStubs(t, func() {
		t.Setenv("ONEFORALL_HOME", "")
		SubfinderFind = func() string { return "/fake/subfinder.exe" }
		SubfinderRun = func(string, string) ([]string, error) {
			return []string{"zzz.m.example", "aaa.m.example"}, nil
		}
		srv := crtShStub(t, `[{"name_value":"mmm.m.example"}]`, 0)
		defer srv.Close()
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		got := Run("m.example", t.TempDir())
		want := []string{"aaa.m.example", "mmm.m.example", "zzz.m.example"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("合并结果 = %v, want %v", got, want)
		}
	})
}

func parityStripCR(s string) string { return strings.ReplaceAll(s, "\r", "") }

// TestRunVerifyWritesOutputs：RunVerify 全链路（本机回环锚点，禁用假域名）。
func TestRunVerifyWritesOutputs(t *testing.T) {
	withStubs(t, func() {
		out := t.TempDir()
		if _, err := netutil.SafeWrite(out, "subdomains.txt", "127.0.0.1\n"); err != nil {
			t.Fatal(err)
		}
		rows := RunVerify(out, 4, false) // doHTTP=false：只验证 DNS
		if len(rows) != 1 || !rows[0].Alive || rows[0].Host != "127.0.0.1" {
			t.Fatalf("rows = %+v", rows)
		}
		txt, err := os.ReadFile(filepath.Join(out, "subdomains_live.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if parityStripCR(string(txt)) != "127.0.0.1\n" {
			t.Fatalf("live.txt = %q", txt)
		}
		jb, err := os.ReadFile(filepath.Join(out, "subdomains_live.json"))
		if err != nil {
			t.Fatal(err)
		}
		var parsed []map[string]any
		if err := json.Unmarshal(jb, &parsed); err != nil || len(parsed) != 1 {
			t.Fatalf("live.json 解析失败: %v %s", err, jb)
		}
	})
}

func TestRunVerifyMissingSource(t *testing.T) {
	if rows := RunVerify(t.TempDir(), 8, false); rows != nil {
		t.Fatalf("缺 subdomains.txt 应返回空: %v", rows)
	}
}
