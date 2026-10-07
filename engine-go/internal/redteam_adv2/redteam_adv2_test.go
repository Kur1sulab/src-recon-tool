// Package redteam_adv2：对抗测试员-2 的攻击验证测试（只读验证，不改生产代码）。
// 零外网：全部流量打本机 httptest；黑洞验证用已关闭的本机端口。
// 声明：本文件为对抗测试产物，key 全部为测试假值，不得替换为真实凭据。
package redteam_adv2

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

const (
	fakeID  = "REDTEAMID-ADV2"
	fakeKey = "REDTEAMKEY-ADV2-NOT-REAL"
)

func setEnv(t *testing.T, k, v string) {
	t.Helper()
	old, had := os.LookupEnv(k)
	if err := os.Setenv(k, v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	})
}

// captureStdout 捕获 Stdout 期间的 fmt.Printf 输出。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// TestICPKeyExfilViaRedirect 复现：icp 把 id/key 拼进 URL query（icp.go:79），
// Fetch{Follow:true} 且无 HopCheck（icp.go:82）——数据源 302 到攻击者可控跳板时，
// 完整 query（含 key）会原样外送。
func TestICPKeyExfilViaRedirect(t *testing.T) {
	var landedQuery chan string
	landing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landedQuery <- r.URL.RawQuery
		_, _ = io.WriteString(w, `{"code":200,"icp":"测试ICP","unit":"测试单位"}`)
	}))
	defer landing.Close()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, landing.URL+"/steal?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer stub.Close()

	oldURL := icp.APIHZURL
	icp.APIHZURL = stub.URL
	t.Cleanup(func() { icp.APIHZURL = oldURL })
	setEnv(t, "APIHZ_ID", fakeID)
	setEnv(t, "APIHZ_KEY", fakeKey)

	landedQuery = make(chan string, 1)
	std := captureStdout(t, func() { icp.QueryICP("example-test.com", 1) })
	// fix2 P1 修复后翻转：icp 改 Follow:false（apihz 接口无需重定向），
	// 302 停留本机（ok=true/status=302 走失败重试），凭据 query 不得离开本机
	select {
	case q := <-landedQuery:
		t.Fatalf("跳板收到了请求——key 仍随 302 外送: %s", q)
	default:
		if !strings.Contains(std, "302") {
			t.Logf("stdout=%s", std)
		}
		t.Logf("修复有效：跳板零请求，凭据未外送（stdout 含 302 失败重试文案=%v）",
			strings.Contains(std, "302"))
	}
}

// TestICPDomainQueryInjection 验证 domain 特殊字符处理：旧版 fmt.Sprintf 直拼
// 可注入第二个 key 参数；现行 buildAPIHZQuery 应做到 percent 编码不可注入。
func TestICPDomainQueryInjection(t *testing.T) {
	var got chan string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.RawQuery
		_, _ = io.WriteString(w, `{"code":200,"icp":"X","unit":"Y"}`)
	}))
	defer stub.Close()
	oldURL := icp.APIHZURL
	icp.APIHZURL = stub.URL
	t.Cleanup(func() { icp.APIHZURL = oldURL })
	setEnv(t, "APIHZ_ID", fakeID)
	setEnv(t, "APIHZ_KEY", fakeKey)

	got = make(chan string, 1)
	var res map[string]any
	std := captureStdout(t, func() { res = icp.QueryICP("a&key=ATTACKER_INJECTED", 1) })
	select {
	case q := <-got:
		if strings.Contains(q, "&key=ATTACKER_INJECTED") || strings.Contains(q, "domain=a&") {
			t.Fatalf("注入仍可行（domain 未编码，出现第二个 key 参数）: %s", q)
		}
		if !strings.Contains(q, "domain=a%26key%3DATTACKER_INJECTED") {
			t.Fatalf("domain 编码形态不符预期: %s", q)
		}
		t.Logf("现行代码已防注入：编码后 query=%s", q)
	default:
		t.Fatalf("stub 未收到请求（stdout=%s res=%+v）", std, res)
	}
}

// TestCheckHTTPURLBlocksIntranetLanding 佐证②：api/paths 模块被 302 打进的
// 192.168.88.1 属于引擎自身入口门禁（allow_private=false）明确拒绝的地址。
func TestCheckHTTPURLBlocksIntranetLanding(t *testing.T) {
	if _, err := netutil.CheckHTTPURL("http://192.168.88.1:18082/land", false); err == nil {
		t.Fatal("CheckHTTPURL(allow_private=false) 竟放行 192.168.88.1 —— 阻断集合失效")
	}
	if _, err := netutil.CheckHTTPURL("http://192.168.88.1:18082/land", true); err != nil {
		t.Fatalf("allow_private=true 应放行（授权内网语义）: %v", err)
	}
}

// TestICPFailureLogNoKey 失败路径日志/落盘不得出现 key（errReason 剥 URL 的契约）。
func TestICPFailureLogNoKey(t *testing.T) {
	oldURL := icp.APIHZURL
	icp.APIHZURL = "http://127.0.0.1:1/dead" // 本机已关闭端口，立即失败且零外网
	t.Cleanup(func() { icp.APIHZURL = oldURL })
	setEnv(t, "APIHZ_ID", fakeID)
	setEnv(t, "APIHZ_KEY", fakeKey)

	out := t.TempDir()
	std := captureStdout(t, func() { icp.RunICP("leak-test.com", out) })
	if strings.Contains(std, fakeKey) || strings.Contains(std, fakeID) {
		t.Fatalf("失败日志泄漏 key/id: %s", std)
	}
	b, err := os.ReadFile(out + string(os.PathSeparator) + "icp_leak-test.com.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), fakeKey) || strings.Contains(string(b), fakeID) {
		t.Fatalf("icp json 泄漏 key/id: %s", b)
	}
	if strings.Contains(string(b), "id=") || strings.Contains(string(b), "key=") {
		t.Fatalf("icp json 疑似携带 query 残留: %s", b)
	}
}
