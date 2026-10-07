package baseline

// baseline_test.go — 聚合器契约测试（全部离线：DNS 走注入假解析器）。
// 覆盖报告 §5.9：--checks 归一化/串行执行/每检查超时/总预算/事件序/产物落盘。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeDNS 可注入假解析器（mailsec/dnsrec 共用接口；按 "方法|名字" 键查表）。
type fakeDNS struct {
	mx   map[string][]*mxRec
	txt  map[string][]string
	err  map[string]error
	late time.Duration // 非 0 时每次查询先睡（模拟超时）
}

type mxRec struct {
	Host string
	Pref uint16
}

func (f *fakeDNS) lookup(key string) error {
	if f.late > 0 {
		time.Sleep(f.late)
	}
	if f.err != nil {
		if e, ok := f.err[key]; ok {
			return e
		}
	}
	return nil
}

func (f *fakeDNS) LookupMX(_ context.Context, domain string) ([]*netMX, error) {
	if err := f.lookup("mx|" + domain); err != nil {
		return nil, err
	}
	out := []*netMX{}
	for _, m := range f.mx[domain] {
		out = append(out, &netMX{Host: m.Host, Pref: m.Pref})
	}
	return out, nil
}

func (f *fakeDNS) LookupTXT(_ context.Context, domain string) ([]string, error) {
	if err := f.lookup("txt|" + domain); err != nil {
		return nil, err
	}
	return f.txt[domain], nil
}

func (f *fakeDNS) LookupHost(_ context.Context, _ string) ([]string, error) {
	if err := f.lookup("host"); err != nil {
		return nil, err
	}
	return []string{"93.184.216.34"}, nil
}

func (f *fakeDNS) LookupIP(_ context.Context, _, _ string) ([]netIPAddr, error) {
	if err := f.lookup("ip"); err != nil {
		return nil, err
	}
	return []netIPAddr{{IP: ipV4(93, 184, 216, 34)}}, nil
}

func (f *fakeDNS) LookupCNAME(_ context.Context, _ string) (string, error) {
	if err := f.lookup("cname"); err != nil {
		return "", err
	}
	return "alias.example.test.", nil
}

func (f *fakeDNS) LookupNS(_ context.Context, _ string) ([]*netNS, error) {
	if err := f.lookup("ns"); err != nil {
		return nil, err
	}
	return []*netNS{{Host: "ns1.example.test."}}, nil
}

func (f *fakeDNS) LookupSRV(_ context.Context, _, _, _ string) (string, []*netSRV, error) {
	if err := f.lookup("srv"); err != nil {
		return "", nil, err
	}
	return "example.test.", []*netSRV{{Target: "sip.example.test.", Port: 5060}}, nil
}

func (f *fakeDNS) LookupAddr(_ context.Context, _ string) ([]string, error) {
	if err := f.lookup("ptr"); err != nil {
		return nil, err
	}
	return []string{"host.example.test."}, nil
}

// quietLogf 静默日志。
func quietLogf(_ string, _ ...any) {}

// recorder 事件记录器。
type recorder struct{ events []string }

func (r *recorder) emit(event, module, detail string) {
	r.events = append(r.events, event+"/"+module+"/"+detail)
}

func TestNormalizeChecks(t *testing.T) {
	// 空 = 全部 8 项（顺序 = checksOrder）
	all, err := NormalizeChecks(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 8 || all[0] != CheckSecHeaders || all[7] != CheckGeoASN {
		t.Errorf("全量检查应为 8 项且按序: %v", all)
	}
	// 别名（报告 §5.1 sec_headers / §5.5 ssl_chain 写法）
	got, err := NormalizeChecks([]string{"sec_headers", "webfiles", "ssl_chain"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{CheckSecHeaders, CheckWebfiles, CheckSSLChain}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("别名归一化 = %v, want %v", got, want)
	}
	// 未知检查名 → error（CLI exit 2）
	if _, err := NormalizeChecks([]string{"nopesec"}); err == nil {
		t.Error("未知检查名应报错")
	}
	// 去重保持序
	got, _ = NormalizeChecks([]string{"mailsec", "mailsec", "geoasn"})
	if len(got) != 2 || got[0] != CheckMailsec || got[1] != CheckGeoASN {
		t.Errorf("去重 = %v", got)
	}
}

func TestRunEventsProductsOffline(t *testing.T) {
	// 单检查（mailsec）+ 注入假 DNS：离线走完聚合，断言事件序与产物。
	old := dns
	fake := &fakeDNS{
		txt: map[string][]string{
			"demo.test":               {"v=spf1 -all"},
			"_dmarc.demo.test":        {"v=DMARC1; p=reject"},
			"s1._domainkey.demo.test": {"v=DKIM1; k=rsa; p=" + b64Pub(t, 1024)},
		},
	}
	dns = fake
	t.Cleanup(func() { dns = old })

	dir := t.TempDir()
	rec := &recorder{}
	o := Options{
		Domain: "demo.test", Out: dir, Checks: []string{CheckMailsec},
		Emit: rec.emit, Logf: quietLogf,
	}
	if err := Run(o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 事件序：start(mailsec) → done(mailsec)；外层 start/done(baseline) 由 cli.Run 负责
	joined := strings.Join(rec.events, " ")
	if !strings.Contains(joined, "start/mailsec/") || !strings.Contains(joined, "done/mailsec/") {
		t.Errorf("事件序缺失内层 start/done: %v", rec.events)
	}
	// 产物：mailsec.json + .txt + evidence 副本
	jp := filepath.Join(dir, "mailsec.json")
	b, err := os.ReadFile(jp)
	if err != nil {
		t.Fatalf("json 产物缺失: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if env["check"] != CheckMailsec {
		t.Errorf("包络 check = %v", env["check"])
	}
	if _, err := os.Stat(filepath.Join(dir, "mailsec.txt")); err != nil {
		t.Errorf("txt 产物缺失: %v", err)
	}
	ev := filepath.Join(dir, "evidence", "baseline", "mailsec.json")
	if _, err := os.Stat(ev); err != nil {
		t.Errorf("证据副本缺失: %v", err)
	}
}

func TestRunSkipsWhenBudgetExhausted(t *testing.T) {
	old := dns
	dns = &fakeDNS{txt: map[string][]string{"demo.test": {"v=spf1 -all"}}}
	t.Cleanup(func() { dns = old })
	// 注入步进时钟：每次 nowFn 调用推进 1 分钟（Windows 时钟粒度粗，
	// 真时钟在同 tick 内 elapsed=0 骗不过 1ns 预算闸）
	oldNow := nowFn
	base := time.Now()
	calls := 0
	nowFn = func() time.Time { calls++; return base.Add(time.Duration(calls) * time.Minute) }
	t.Cleanup(func() { nowFn = oldNow })

	dir := t.TempDir()
	rec := &recorder{}
	o := Options{
		Domain: "demo.test", Out: dir, Checks: []string{CheckMailsec, CheckDNSRec},
		TotalBudget: 30 * time.Second, // 第一次闸口时已「走」1 分钟 ≥ 30s → 立即耗尽
		Emit:        rec.emit, Logf: quietLogf,
	}
	if err := Run(o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	joined := strings.Join(rec.events, " ")
	if !strings.Contains(joined, "skipped/mailsec/") || !strings.Contains(joined, "skipped/dnsrec/") {
		t.Errorf("预算耗尽应 skipped: %v", rec.events)
	}
	// skipped 不落盘（缺文件 = 未运行，桌面空态语义）
	if _, err := os.Stat(filepath.Join(dir, "mailsec.json")); !os.IsNotExist(err) {
		t.Error("skipped 检查不应落盘")
	}
}

func TestRunPerCheckTimeout(t *testing.T) {
	old := dns
	dns = &fakeDNS{late: 300 * time.Millisecond, txt: map[string][]string{"demo.test": {"v=spf1 -all"}}}
	t.Cleanup(func() { dns = old })

	dir := t.TempDir()
	rec := &recorder{}
	o := Options{
		Domain: "demo.test", Out: dir, Checks: []string{CheckMailsec},
		PerCheckTimeout: 30 * time.Millisecond,
		Emit:            rec.emit, Logf: quietLogf,
	}
	if err := Run(o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	joined := strings.Join(rec.events, " ")
	if !strings.Contains(joined, "fail/mailsec/") {
		t.Errorf("超时应 fail 事件: %v", rec.events)
	}
	// 超时落盘 error 包络（失败态，不编造数据）
	b, err := os.ReadFile(filepath.Join(dir, "mailsec.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "超时") {
		t.Errorf("超时包络应含超时错误: %s", b)
	}
}

func TestRunUnknownCheck(t *testing.T) {
	o := Options{Domain: "demo.test", Out: t.TempDir(), Checks: []string{"nope"}}
	if err := Run(o); !errors.Is(err, ErrUnknownCheck) {
		t.Errorf("未知检查应 ErrUnknownCheck, 得 %v", err)
	}
}

func TestRunCheckFailureDoesNotBreakOthers(t *testing.T) {
	// mailsec DNS 全挂 → fail 事件；dnsrec 照常 done（fail 不中断）
	old := dns
	errAll := errors.New("dial tcp: connection refused")
	dns = &fakeDNS{err: map[string]error{
		"txt|demo.test": errAll, "txt|_dmarc.demo.test": errAll,
		"txt|s1._domainkey.demo.test": errAll, "txt|default._domainkey.demo.test": errAll,
		"txt|google._domainkey.demo.test": errAll, "txt|selector1._domainkey.demo.test": errAll,
		"txt|selector2._domainkey.demo.test": errAll, "txt|k1._domainkey.demo.test": errAll,
		"txt|s2._domainkey.demo.test": errAll, "txt|dkim._domainkey.demo.test": errAll,
		"mx|demo.test": errAll,
		"host":         errAll, "ip": errAll, "cname": errAll, "ns": errAll,
		"srv": errAll, "ptr": errAll,
	}}
	t.Cleanup(func() { dns = old })

	dir := t.TempDir()
	rec := &recorder{}
	o := Options{
		Domain: "demo.test", Out: dir,
		Checks: []string{CheckMailsec, CheckDNSRec},
		Emit:   rec.emit, Logf: quietLogf,
	}
	if err := Run(o); err != nil {
		t.Fatalf("检查级失败不应改变聚合退出: %v", err)
	}
	joined := strings.Join(rec.events, " ")
	if !strings.Contains(joined, "fail/mailsec/") {
		t.Errorf("mailsec 应 fail: %v", rec.events)
	}
	if !strings.Contains(joined, "done/dnsrec/") {
		t.Errorf("dnsrec 应照常 done: %v", rec.events)
	}
}
