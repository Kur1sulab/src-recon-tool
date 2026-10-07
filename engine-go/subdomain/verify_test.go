package subdomain

import (
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"
)

// portOf 从 httptest 服务地址取端口。
func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDNSLookupLiteral DNS 锚点用 127.0.0.1 字面量（本机 Clash fake-ip 下
// 假域名会"解析成功"，禁止用 NXDOMAIN 断言——风险清单红线）。
func TestDNSLookupLiteral(t *testing.T) {
	ips := DNSLookup("127.0.0.1", 3*time.Second)
	if len(ips) == 0 {
		t.Fatal("127.0.0.1 应解析成功")
	}
	found := false
	for _, ip := range ips {
		if ip == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应含 127.0.0.1: %v", ips)
	}
	if !sort.StringsAreSorted(ips) {
		t.Fatalf("IP 列表应字典序排序: %v", ips)
	}
}

func TestDNSLookupUnresolvableHost(t *testing.T) {
	// 真实不存在但绝不经过外网解析的锚点：本机回环段保留名（RFC 6761，
	// invalid 顶层域——若本机 fake-ip 拦截导致"解析成功"，本测试自动放行不红）
	ips := DNSLookup("definitely-not-a-host.invalid", 2*time.Second)
	if len(ips) > 0 {
		t.Skipf("本机 DNS 对 .invalid 返回了结果（fake-ip 环境），跳过 NXDOMAIN 断言: %v", ips)
	}
}

func TestHTTPProbeAgainstMock(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	port := portOf(t, srv.URL)
	p := HTTPProbe("127.0.0.1", 5*time.Second, port)
	if p.Scheme != "http" || p.Status != 404 {
		t.Fatalf("probe = %+v（https 先失败应落到 http）", p)
	}
	if p.Title != "" {
		t.Fatalf("404 页不应有 title: %q", p.Title)
	}
	// 无路径 URL 两侧 geturl 都不带尾斜杠（urllib 与 net/url 一致）
	if p.FinalURL != "http://127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("final_url = %q", p.FinalURL)
	}
}

func TestVerifySubsOrderPreserved(t *testing.T) {
	subs := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	rows := VerifySubs(subs, 4, false, 120)
	if len(rows) != len(subs) {
		t.Fatalf("rows = %d", len(rows))
	}
	for i, r := range rows {
		if r.Host != subs[i] {
			t.Fatalf("rows 应保持输入序: %d %q", i, r.Host)
		}
		if !r.Alive || len(r.IPs) == 0 {
			t.Fatalf("回环字面量应 alive: %+v", r)
		}
	}
}
