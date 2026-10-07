package baseline

// mailsec_test.go — 邮件安全检查（§5.3）验收：
//   1. 注入固定记录：+all 判宽松、v=spf1 -all 判严、无 DMARC 判可伪造、p=reject 判严。
//   2. DKIM 公钥位数解析（2048/1024 样例）正确。
//   3. SPF include/redirect 最多展开 2 层。
//   4. MX 服务商指纹命中。
// 全部离线（dns 注入假解析器；联网集成用例见 RECON_NET_TESTS 门控文件）。

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// txtOnlyDNS 只带 TXT 记录的假解析器（其余方法返回零值+错误）。
type txtOnlyDNS struct {
	fakeDNS
}

func (txtOnlyDNS) LookupMX(context.Context, string) ([]*netMX, error) {
	return nil, errors.New("no mx")
}

// mkMailsec 构造注入记录并跑 RunMailsec。
func mkMailsec(t *testing.T, txt map[string][]string) Result {
	t.Helper()
	old := dns
	dns = &fakeDNS{txt: txt, mx: map[string][]*mxRec{
		"demo.test": {{Host: "mxbiz1.qq.com", Pref: 5}},
	}}
	t.Cleanup(func() { dns = old })
	return RunMailsec(Options{Domain: "demo.test", Logf: quietLogf})
}

func TestMailsecSPFAllVerdicts(t *testing.T) {
	// +all + DMARC p=quarantine → 策略宽松（warn）（可伪造档已被 DMARC 在场挡住）
	res := mkMailsec(t, map[string][]string{
		"demo.test":        {"v=spf1 ip4:1.2.3.4 +all"},
		"_dmarc.demo.test": {"v=DMARC1; p=quarantine"},
	})
	if res.Conclusion.Level != LevelWarn || !strings.Contains(res.Conclusion.Text, "宽松") {
		t.Errorf("+all 应判策略宽松: %+v", res.Conclusion)
	}
	// v=spf1 -all + 无 DMARC → 可伪造（fail，可伪造优先于 SPF 严）
	res = mkMailsec(t, map[string][]string{
		"demo.test": {"v=spf1 -all"},
	})
	if res.Conclusion.Level != LevelFail || !strings.Contains(res.Conclusion.Text, "可伪造") {
		t.Errorf("无 DMARC 应判可伪造: %+v", res.Conclusion)
	}
	// v=spf1 -all + p=reject → 正常（ok）
	res = mkMailsec(t, map[string][]string{
		"demo.test":        {"v=spf1 -all"},
		"_dmarc.demo.test": {"v=DMARC1; p=reject"},
	})
	if res.Conclusion.Level != LevelOK {
		t.Errorf("p=reject 应判正常: %+v", res.Conclusion)
	}
	// p=none → 可伪造
	res = mkMailsec(t, map[string][]string{
		"demo.test":        {"v=spf1 -all"},
		"_dmarc.demo.test": {"v=DMARC1; p=none"},
	})
	if res.Conclusion.Level != LevelFail || !strings.Contains(res.Conclusion.Text, "可伪造") {
		t.Errorf("p=none 应判可伪造: %+v", res.Conclusion)
	}
	// p=reject; pct=50 → 部分生效（warn）
	res = mkMailsec(t, map[string][]string{
		"demo.test":        {"v=spf1 -all"},
		"_dmarc.demo.test": {"v=DMARC1; p=reject; pct=50"},
	})
	if res.Conclusion.Level != LevelWarn || !strings.Contains(res.Conclusion.Text, "pct=50") {
		t.Errorf("pct=50 应分档 warn: %+v", res.Conclusion)
	}
}

func TestSPFParse(t *testing.T) {
	spf := parseSPF("v=spf1 include:_spf.a.test redirect=_b.test ~all")
	if spf.All != "~all" || len(spf.Includes) != 1 || spf.Includes[0] != "_spf.a.test" || spf.Redirect != "_b.test" {
		t.Errorf("SPF 解析 = %+v", spf)
	}
	if lvl, _ := spfAllVerdict("+all"); lvl != LevelFail {
		t.Errorf("+all 应 fail 级")
	}
	if lvl, _ := spfAllVerdict("?all"); lvl != LevelInfo {
		t.Errorf("?all 应 info 级")
	}
	if lvl, _ := spfAllVerdict(""); lvl != LevelWarn {
		t.Errorf("缺 all 应 warn 级")
	}
}

func TestWalkSPFDepth(t *testing.T) {
	old := dns
	dns = &fakeDNS{txt: map[string][]string{
		"l1.test": {"v=spf1 include:l2.test -all"},
		"l2.test": {"v=spf1 include:l3.test -all"},
		"l3.test": {"v=spf1 include:l4.test -all"}, // 第 3 层，不应展开
		"l4.test": {"v=spf1 -all"},
	}}
	t.Cleanup(func() { dns = old })
	var out []string
	walkSPF("v=spf1 include:l1.test -all", 1, map[string]bool{}, &out)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "l1.test") || !strings.Contains(joined, "l2.test") || !strings.Contains(joined, "l3.test") {
		t.Errorf("前 2 层应展开（l1→l2→l3）: %q", joined)
	}
	if strings.Contains(joined, "l4.test") {
		t.Errorf("第 3 层不应展开（上限 2 层）: %q", joined)
	}
}

func TestDKIMKeyBits(t *testing.T) {
	for _, bits := range []int{2048, 1024} {
		got, err := dkimKeyBits(b64Pub(t, bits))
		if err != nil {
			t.Fatalf("%d 位解析失败: %v", bits, err)
		}
		if got != bits {
			t.Errorf("公钥位数 = %d, want %d", got, bits)
		}
	}
	if _, err := dkimKeyBits("!!!not-base64!!!"); err == nil {
		t.Error("坏 base64 应报错")
	}
}

func TestMailsecDKIMRows(t *testing.T) {
	res := mkMailsec(t, map[string][]string{
		"demo.test":               {"v=spf1 -all"},
		"_dmarc.demo.test":        {"v=DMARC1; p=reject"},
		"s1._domainkey.demo.test": {"v=DKIM1; k=rsa; p=" + b64Pub(t, 2048)},
		"k1._domainkey.demo.test": {"v=DKIM1; k=rsa; p="}, // 公钥撤销
	})
	dkim := res.Data["dkim"].([]map[string]any)
	if len(dkim) != 2 {
		t.Fatalf("应命中 2 个 selector: %v", dkim)
	}
	bitsOK := false
	for _, row := range dkim {
		if row["selector"] == "s1" && row["bits"] == 2048 {
			bitsOK = true
		}
		if row["selector"] == "k1" && !strings.Contains(row["note"].(string), "撤销") {
			t.Errorf("p= 空 应记撤销: %v", row)
		}
	}
	if !bitsOK {
		t.Errorf("s1 应记 2048 位: %v", dkim)
	}
}

func TestMailsecMXVendor(t *testing.T) {
	if v := mxVendor("mxbiz1.qq.com"); v != "腾讯企业邮箱" {
		t.Errorf("mxbiz1.qq.com → %q", v)
	}
	if v := mxVendor("mx1.QQ.com."); v != "腾讯" {
		t.Errorf("泛后缀 qq.com → %q, 得 %q", "腾讯", v)
	}
	if v := mxVendor("mx.mail.netease.com"); v == "" {
		t.Log("netease 泛后缀未覆盖（可扩表）")
	}
	if v := mxVendor("mail.unknown.test"); v != "" {
		t.Errorf("未知名不应命中: %q", v)
	}
}

func TestMailsecDNSAllFail(t *testing.T) {
	old := dns
	errAll := errors.New("dial: connection refused")
	dns = &fakeDNS{err: map[string]error{
		"txt|demo.test": errAll, "txt|_dmarc.demo.test": errAll,
	}}
	t.Cleanup(func() { dns = old })
	// dkim 8 selector 也要全失败才判全挂 —— fake 默认无记录返回 nil,nil，
	// 这里用会失败的桩：全部 key 缺失时 lookup 返回注册过的 err
	res := RunMailsec(Options{Domain: "demo.test", Logf: quietLogf})
	// TXT 全挂但 DKIM 未挂（nil,nil）→ 不算全失败，走正常路径
	if res.Error != "" {
		t.Logf("DKIM 在场语义: %s", res.Error)
	}
	// 全挂桩
	allFail := &allFailDNS{}
	dns = allFail
	res = RunMailsec(Options{Domain: "demo.test", Logf: quietLogf})
	if res.Error == "" || !strings.Contains(res.Error, "DNS 查询全部失败") {
		t.Errorf("全挂应置 Error: %+v", res)
	}
	if res.Conclusion.Level != LevelFail {
		t.Errorf("全挂结论应 fail: %+v", res.Conclusion)
	}
}

// allFailDNS 所有查询都失败。
type allFailDNS struct{}

func (allFailDNS) LookupMX(context.Context, string) ([]*netMX, error) {
	return nil, errors.New("refused")
}
func (allFailDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("refused")
}
func (allFailDNS) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("refused")
}
func (allFailDNS) LookupIP(context.Context, string, string) ([]netIPAddr, error) {
	return nil, errors.New("refused")
}
func (allFailDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", errors.New("refused")
}
func (allFailDNS) LookupNS(context.Context, string) ([]*netNS, error) {
	return nil, errors.New("refused")
}
func (allFailDNS) LookupSRV(context.Context, string, string, string) (string, []*netSRV, error) {
	return "", nil, errors.New("refused")
}
func (allFailDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errors.New("refused")
}
