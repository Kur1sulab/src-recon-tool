package baseline

// dnsrec_test.go — DNS 记录检查（§5.6）验收：
//   1. mock resolver 注入固定记录，8 类字段渲染断言。
//   2. --doh 关闭时 SOA/CAA/DS/DNSKEY 显示「未查（--doh 未开）」，不编造空记录。
//   4. 查询失败类型（NXDOMAIN/超时）分字段记录。
//  + KnownA 去重（verify 已解析 A 不二次查询）；DoH JSON 解析 fixture。
// 全部离线。

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// recFake 全字段可配的假解析器（dnsrec 专用）。
type recFake struct {
	hostErr error // A 查询错误
	a       []string
	aaaa    []string
	cname   string
	mx      []*mxRec
	ns      []string
	txt     []string
	srv     []*netSRV
	ptr     []string
	hostCalls int
}

func (f *recFake) LookupMX(context.Context, string) ([]*netMX, error) {
	out := []*netMX{}
	for _, m := range f.mx {
		out = append(out, &netMX{Host: m.Host, Pref: m.Pref})
	}
	return out, nil
}
func (f *recFake) LookupTXT(context.Context, string) ([]string, error) { return f.txt, nil }
func (f *recFake) LookupHost(context.Context, string) ([]string, error) {
	f.hostCalls++
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	return f.a, nil
}
func (f *recFake) LookupIP(_ context.Context, network, _ string) ([]netIPAddr, error) {
	if network == "ip6" {
		out := []netIPAddr{}
		for _, s := range f.aaaa {
			out = append(out, netIPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	}
	return nil, errors.New("unreachable")
}
func (f *recFake) LookupCNAME(context.Context, string) (string, error) { return f.cname, nil }
func (f *recFake) LookupNS(context.Context, string) ([]*netNS, error) {
	out := []*netNS{}
	for _, n := range f.ns {
		out = append(out, &netNS{Host: n})
	}
	return out, nil
}
func (f *recFake) LookupSRV(context.Context, string, string, string) (string, []*netSRV, error) {
	return "demo.test.", f.srv, nil
}
func (f *recFake) LookupAddr(context.Context, string) ([]string, error) { return f.ptr, nil }

func recFixture() *recFake {
	return &recFake{
		a:     []string{"93.184.216.34"},
		aaaa:  []string{"2606:2800:220:1:248:1893:25c8:1946"},
		cname: "alias.demo.test.",
		mx:    []*mxRec{{Host: "mx1.demo.test.", Pref: 10}},
		ns:    []string{"ns1.demo.test."},
		txt:   []string{"v=spf1 -all", "site-verify=abc"},
		srv:   []*netSRV{{Target: "sip.demo.test.", Port: 5060}},
		ptr:   []string{"host.demo.test."},
	}
}

func TestDNSRecEightTypes(t *testing.T) {
	old := dns
	f := recFixture()
	dns = f
	t.Cleanup(func() { dns = old })

	res := RunDNSRec(Options{Domain: "demo.test", Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("不应失败: %s", res.Error)
	}
	if got := res.Data["a"].([]string); len(got) != 1 || got[0] != "93.184.216.34" {
		t.Errorf("a = %v", got)
	}
	if got := res.Data["aaaa"].([]string); len(got) != 1 {
		t.Errorf("aaaa = %v", got)
	}
	if res.Data["cname"] != "alias.demo.test" {
		t.Errorf("cname = %v", res.Data["cname"])
	}
	mx := res.Data["mx"].([]map[string]any)
	if len(mx) != 1 || mx[0]["host"] != "mx1.demo.test" || mx[0]["pref"] != uint16(10) {
		t.Errorf("mx = %v", mx)
	}
	if ns := res.Data["ns"].([]string); len(ns) != 1 || ns[0] != "ns1.demo.test" {
		t.Errorf("ns = %v", ns)
	}
	if txt := res.Data["txt"].([]string); len(txt) != 2 {
		t.Errorf("txt = %v", txt)
	}
	srv := res.Data["srv"].([]map[string]any)
	if len(srv) != len(srvProbeList) { // fake 对 5 个探测名都返回同一条记录
		t.Errorf("srv = %v", srv)
	}
	if srv[0]["target"] != "sip.demo.test" || srv[0]["port"] != uint16(5060) {
		t.Errorf("srv[0] = %v", srv[0])
	}
	ptr := res.Data["ptr"].(map[string]any)
	if names, ok := ptr["93.184.216.34"].([]string); !ok || len(names) != 1 {
		t.Errorf("ptr = %v", ptr)
	}
}

func TestDNSRecDoHOff(t *testing.T) {
	old := dns
	dns = recFixture()
	t.Cleanup(func() { dns = old })

	res := RunDNSRec(Options{Domain: "demo.test", DoH: false, Logf: quietLogf})
	for _, k := range []string{"soa", "caa", "ds", "dnskey"} {
		if res.Data[k] != "未查（--doh 未开）" {
			t.Errorf("%s 应为未查标记, 得 %v", k, res.Data[k])
		}
	}
}

func TestDNSRecDoHOn(t *testing.T) {
	old := dns
	dns = recFixture()
	t.Cleanup(func() { dns = old })

	oldBase, oldFetch := DoHBase, dohFetch
	DoHBase = "http://127.0.0.1:1/resolve"
	dohFetch = func(rawURL string, _ time.Duration) (map[string]any, error) {
		if strings.Contains(rawURL, "type=6") { // SOA
			return map[string]any{"Status": float64(0), "Answer": []any{
				map[string]any{"name": "demo.test.", "type": float64(6), "data": "ns1.demo.test. hostmaster 1 2 3 4 5"},
			}}, nil
		}
		if strings.Contains(rawURL, "type=257") { // CAA
			return map[string]any{"Status": float64(0), "Answer": []any{
				map[string]any{"name": "demo.test.", "type": float64(257), "data": `0 issue "letsencrypt.org"`},
			}}, nil
		}
		// DS/DNSKEY：无记录（Status=0 无 Answer）
		return map[string]any{"Status": float64(0)}, nil
	}
	t.Cleanup(func() { DoHBase, dohFetch = oldBase, oldFetch })

	res := RunDNSRec(Options{Domain: "demo.test", DoH: true, Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("DoH 用例不应失败: %s", res.Error)
	}
	soa := res.Data["soa"].([]string)
	if len(soa) != 1 || !strings.Contains(soa[0], "ns1.demo.test") {
		t.Errorf("soa = %v", soa)
	}
	caa := res.Data["caa"].([]string)
	if len(caa) != 1 || !strings.Contains(caa[0], "letsencrypt.org") {
		t.Errorf("caa = %v", caa)
	}
	if res.Data["ds"] != "无记录" || res.Data["dnskey"] != "无记录" {
		t.Errorf("无记录应如实输出: ds=%v dnskey=%v", res.Data["ds"], res.Data["dnskey"])
	}
	if !strings.Contains(res.Data["dnssec"].(string), "未发现") {
		t.Errorf("dnssec = %v", res.Data["dnssec"])
	}
}

func TestDNSRecErrClassification(t *testing.T) {
	old := dns
	f := recFixture()
	f.hostErr = &net.DNSError{Err: "no such host", IsNotFound: true}
	dns = f
	t.Cleanup(func() { dns = old })

	res := RunDNSRec(Options{Domain: "demo.test", Logf: quietLogf})
	errs := res.Data["errors"].(map[string]string)
	if errs["a"] != "NXDOMAIN" {
		t.Errorf("NXDOMAIN 分类 = %q", errs["a"])
	}
	// 超时形态
	f2 := recFixture()
	f2.hostErr = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	dns = f2
	res = RunDNSRec(Options{Domain: "demo.test", Logf: quietLogf})
	errs = res.Data["errors"].(map[string]string)
	if errs["a"] != "查询超时" {
		t.Errorf("超时分类 = %q", errs["a"])
	}
	if a := res.Data["a"].([]string); len(a) != 0 {
		t.Errorf("失败字段应空列表: %v", a)
	}
}

func TestDNSRecKnownADedup(t *testing.T) {
	old := dns
	f := recFixture()
	dns = f
	t.Cleanup(func() { dns = old })

	RunDNSRec(Options{Domain: "demo.test", KnownA: map[string][]string{
		"demo.test": {"1.2.3.4"},
	}, Logf: quietLogf})
	if f.hostCalls != 0 {
		t.Errorf("KnownA 在场时不应再查 A: hostCalls=%d", f.hostCalls)
	}
}
