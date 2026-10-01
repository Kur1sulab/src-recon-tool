package asset

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

func withCheckAllow(t *testing.T) {
	t.Helper()
	old := checkURL
	checkURL = func(u string) (string, error) { return u, nil } // 测试放行（打 127.0.0.1 stub）
	t.Cleanup(func() { checkURL = old })
}

func TestParseFofaResults(t *testing.T) {
	got := ParseFofaResults([][]any{
		{"example.com:443", "1.2.3.4", float64(443), "https"},
		{nil, "5.6.7.8", float64(80), "http"}, // Python f"{None}" → "None"
	})
	want := []string{"example.com:443|1.2.3.4|443|https", "None|5.6.7.8|80|http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseHunterArr(t *testing.T) {
	got := ParseHunterArr([]map[string]any{
		{"domain": "a.com", "ip": "1.1.1.1", "port": float64(443), "protocol": "https"},
		{"domain": "b.com"}, // 缺键取 ""（a.get(k,'')）
	})
	want := []string{"a.com|1.1.1.1|443|https", "b.com|||"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRunAssetWithStubs(t *testing.T) {
	withCheckAllow(t)
	t.Setenv("FOFA_EMAIL", "test@example.com")
	t.Setenv("FOFA_KEY", "fake-key")
	t.Setenv("HUNTER_KEY", "fake-key")
	var fofaHits, hunterHits int
	fofa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("email") != "test@example.com" || q.Get("size") != "100" ||
			q.Get("fields") != "host,ip,port,protocol" {
			t.Errorf("FOFA 参数缺失: %v", q)
		}
		fofaHits++
		_, _ = w.Write([]byte(`{"error":false,"results":[["a.com:443","1.2.3.4",443,"https"],["b.com","5.6.7.8",80,"http"]]}`))
	}))
	defer fofa.Close()
	hunter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hunterHits++
		_, _ = w.Write([]byte(`{"code":200,"data":{"arr":[{"domain":"a.com","ip":"1.2.3.4","port":443,"protocol":"https"}]}}`))
	}))
	defer hunter.Close()
	oldF, oldH := FofaBase, HunterBase
	FofaBase = fofa.URL + "/all?%s"
	HunterBase = hunter.URL + "/search?%s"
	t.Cleanup(func() { FofaBase, HunterBase = oldF, oldH })

	out := t.TempDir()
	RunAsset("example.com", out)
	if fofaHits != 1 || hunterHits != 1 {
		t.Fatalf("各源应恰好请求一次: fofa=%d hunter=%d", fofaHits, hunterHits)
	}
	b, err := os.ReadFile(filepath.Join(out, "assets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	// FOFA 2 条 + Hunter 1 条；Hunter 的 "a.com|1.2.3.4|443|https" 与 FOFA 的
	// "a.com:443|1.2.3.4|443|https" 是不同字符串 → dict.fromkeys 不合并，共 3 行
	want := []string{"a.com:443|1.2.3.4|443|https", "b.com|5.6.7.8|80|http", "a.com|1.2.3.4|443|https"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assets.txt = %v, want %v", got, want)
	}
}

func TestRunAssetErrorBranches(t *testing.T) {
	withCheckAllow(t)
	t.Setenv("FOFA_EMAIL", "t@e.com")
	t.Setenv("FOFA_KEY", "k")
	t.Setenv("HUNTER_KEY", "k")
	fofa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":true,"errmsg":"quota exceeded"}`))
	}))
	defer fofa.Close()
	hunter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":401,"message":"invalid api-key"}`))
	}))
	defer hunter.Close()
	oldF, oldH := FofaBase, HunterBase
	FofaBase, HunterBase = fofa.URL+"/all?%s", hunter.URL+"/search?%s"
	t.Cleanup(func() { FofaBase, HunterBase = oldF, oldH })
	// 两源都报错误分支 → 空结果 + assets.txt 空文件，不 panic
	RunAsset("example.com", t.TempDir())
}

func TestRunAssetUnconfigured(t *testing.T) {
	t.Setenv("FOFA_EMAIL", "")
	t.Setenv("FOFA_KEY", "")
	t.Setenv("HUNTER_KEY", "")
	// 未配置：不发起任何请求，直接提示跳过（不阻断）
	RunAsset("example.com", t.TempDir())
}

// TestRunAssetPrivateBlocked 校验层默认阻断私网（asset.py:30/47 默认 allow_private=False）。
func TestRunAssetPrivateBlocked(t *testing.T) {
	if _, err := netutil.CheckHTTPURL("http://127.0.0.1:1/x", false); err == nil {
		t.Fatal("默认应阻断环回地址")
	}
}
