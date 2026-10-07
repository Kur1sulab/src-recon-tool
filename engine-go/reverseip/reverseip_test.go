package reverseip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestParseHackerTargetGolden 黄金用例逐条移植 test_new_modules.py:22-37。
func TestParseHackerTargetGolden(t *testing.T) {
	raw := "xycovo.com\n" +
		"www.xycovo.com\n" +
		"0.0.d.5.9.6.0.7.4.0.1.0.0.2.ip6.arpa\n" +
		"not a domain\n" +
		"api.example.com.\n" +
		"\n" +
		"XYCOVO.COM\n"
	got := ParseHackerTarget(raw)
	want := []string{"api.example.com", "www.xycovo.com", "xycovo.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
	if ParseHackerTarget("") != nil {
		t.Fatal("空输入应返回空")
	}
	if got := ParseHackerTarget("error check your search parameter"); got != nil {
		t.Fatalf("错误文案行应全被过滤: %v", got)
	}
}

func TestValidDomainLabelRules(t *testing.T) {
	cases := map[string]bool{
		"xycovo.com":      true,
		"a-b.co":          true,
		"-bad.com":        false, // 首段以 - 开头（原 (?!-)）
		"bad-.com":        false, // 首段以 - 结尾（原 (?<!-)）
		"ok.example.com":  true,
		"single":          false, // 少于 2 段
		"under_score.com": false, // 非法字符
	}
	for name, want := range cases {
		if got := validDomain(name); got != want {
			t.Errorf("validDomain(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestFetchRetryThenSuccess(t *testing.T) {
	oldSleep := retrySleep
	retrySleep = func(time.Duration) {} // 免退避等待
	t.Cleanup(func() { retrySleep = oldSleep })
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("a.example.com\nb.example.com\n"))
	}))
	defer srv.Close()
	oldBase := HackertargetBase
	HackertargetBase = srv.URL + "/?q=%s"
	t.Cleanup(func() { HackertargetBase = oldBase })

	got := ReverseIP("1.2.3.4")
	if n.Load() != 3 {
		t.Fatalf("重试计数 = %d, want 3（前两次 502）", n.Load())
	}
	if len(got) != 2 {
		t.Fatalf("重试成功后结果 = %v", got)
	}
}

func TestRunReverseWritesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("xycovo.com\nwww.xycovo.com\n0.0.0.0.0.ip6.arpa\n"))
	}))
	defer srv.Close()
	oldBase := HackertargetBase
	HackertargetBase = srv.URL + "/?q=%s"
	t.Cleanup(func() { HackertargetBase = oldBase })
	out := t.TempDir()
	doms := RunReverse("47.100.49.228", out)
	if len(doms) != 2 {
		t.Fatalf("doms = %v", doms)
	}
	b, err := os.ReadFile(filepath.Join(out, "reverse_domains.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "www.xycovo.com\nxycovo.com\n" {
		t.Fatalf("文件内容 = %q", b)
	}
}
