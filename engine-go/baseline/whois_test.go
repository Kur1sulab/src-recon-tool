package baseline

// whois_test.go — WHOIS 注册信息检查（§5.7）验收：
//   1. RDAP JSON fixture 解析断言（events/entities/nameservers）。
//   2. 43 端口 .com/.cn 文本 fixture 正则抽取断言。
//   4. RDAP 不可达自动落 43 端口（stub whoisQuery 喂 referral 链）。
//   5. 超时 fail 静默（Error 置位不 panic，不阻塞聚合——聚合语义见聚合器测试）。
// 全部离线（rdapFetch/whoisQuery 注入桩）。

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const rdapFixture = `{
  "status": ["client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}
  ],
  "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "EXAMPLE LLC"]]]},
    {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]]]}
  ],
  "nameservers": [{"ldhName": "A.IANA-SERVERS.ORG"}, {"ldhName": "B.IANA-SERVERS.ORG"}]
}`

func TestParseRDAP(t *testing.T) {
	var m map[string]any
	if err := jsonUnmarshal(rdapFixture, &m); err != nil {
		t.Fatal(err)
	}
	w := parseRDAP(m)
	if w.Registrar != "RESERVED-IANA" {
		t.Errorf("registrar = %q", w.Registrar)
	}
	if w.Events["registration"] != "1995-08-14T04:00:00Z" || w.Events["expiration"] != "2099-08-13T04:00:00Z" ||
		w.Events["last changed"] != "2026-01-01T00:00:00Z" {
		t.Errorf("events = %v", w.Events)
	}
	if len(w.Nameservers) != 2 || w.Nameservers[0] != "a.iana-servers.org" {
		t.Errorf("nameservers = %v", w.Nameservers)
	}
	if len(w.Status) != 1 || w.Status[0] != "client transfer prohibited" {
		t.Errorf("status = %v", w.Status)
	}
}

// .com（Verisign）与 .cn（CNNIC）文本 fixture。
const verisignText = `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.example
Registrar: RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY
Updated Date: 2024-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.ORG
Name Server: B.IANA-SERVERS.ORG
`

const cnnicText = `Domain Name: example.cn
Registrar: 厦门易名科技股份有限公司
Creation Date: 2003-03-17 12:20:05
Expiry Date: 2027-03-17 12:48:36
Name Server: a.example.cn
Name Server: b.example.cn
`

func TestParseWhoisText(t *testing.T) {
	w := parseWhoisText(verisignText)
	if w.Registrar != "RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY" {
		t.Errorf("registrar = %q", w.Registrar)
	}
	if !strings.HasPrefix(w.Creation, "1995-08-14") || !strings.HasPrefix(w.Expiry, "2027-08-13") {
		t.Errorf("dates = %q / %q", w.Creation, w.Expiry)
	}
	if len(w.NameServers) != 2 || w.NameServers[0] != "A.IANA-SERVERS.ORG" {
		t.Errorf("ns = %v", w.NameServers)
	}
	// CNNIC 中文注册商
	w2 := parseWhoisText(cnnicText)
	if w2.Registrar != "厦门易名科技股份有限公司" {
		t.Errorf("cn registrar = %q", w2.Registrar)
	}
	if !strings.HasPrefix(w2.Expiry, "2027-03-17") {
		t.Errorf("cn expiry = %q", w2.Expiry)
	}
	if len(w2.NameServers) != 2 {
		t.Errorf("cn ns = %v", w2.NameServers)
	}
}

func TestExtractReferral(t *testing.T) {
	if got := extractReferral("refer: WHOIS.VERISIGN-GRS.COM\nsome text"); got != "WHOIS.VERISIGN-GRS.COM" {
		t.Errorf("refer = %q", got)
	}
	if got := extractReferral("Registrar WHOIS Server: whois.registrar.example\n"); got != "whois.registrar.example" {
		t.Errorf("registrar server = %q", got)
	}
	if got := extractReferral("ReferralServer: whois://whois.cnnic.cn\n"); got != "whois.cnnic.cn" {
		t.Errorf("referral server = %q", got)
	}
	if got := extractReferral("no referral here"); got != "" {
		t.Errorf("无 referral 应空: %q", got)
	}
}

// whoisStub 按服务器分发应答的桩（referral 链用例）。
type whoisStub struct {
	byServer map[string]string
	err      error
	servers  []string
}

func (s *whoisStub) query(server, q string, _ time.Duration) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	s.servers = append(s.servers, server)
	if body, ok := s.byServer[server]; ok {
		return body, nil
	}
	return "no matching referral", nil
}

func TestWhoisFallback43(t *testing.T) {
	// RDAP 不可达 → 自动落 43 端口，沿 IANA→注册局→注册商两级 referral
	stub := &whoisStub{byServer: map[string]string{
		"whois.iana.org":          "refer: whois.verisign-grs.com\nremarks: IANA",
		"whois.verisign-grs.com":  "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.registrar.example\nRegistrar: VERISIGN-DOM\n",
		"whois.registrar.example": verisignText,
	}}
	oldRDAP, oldQuery := rdapFetch, whoisQuery
	rdapFetch = func(string, time.Duration) (map[string]any, error) { return nil, errors.New("rdap unreachable") }
	whoisQuery = stub.query
	t.Cleanup(func() { rdapFetch, whoisQuery = oldRDAP, oldQuery })

	res := RunWhois(Options{Domain: "example.com", Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("43 回退用例不应失败: %s", res.Error)
	}
	if res.Data["source"] != "whois43" {
		t.Errorf("source = %v", res.Data["source"])
	}
	if len(stub.servers) != 3 {
		t.Errorf("referral 链应 3 跳: %v", stub.servers)
	}
	txt := res.Data["whois"].(whoisText)
	if txt.Registrar != "RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY" || !strings.HasPrefix(txt.Expiry, "2027-08-13") {
		t.Errorf("最终文本抽取 = %+v", txt)
	}
}

func TestWhoisRDAPPath(t *testing.T) {
	oldRDAP := rdapFetch
	rdapFetch = func(rawURL string, _ time.Duration) (map[string]any, error) {
		if !strings.Contains(rawURL, "example.com") {
			return nil, errors.New("bad url")
		}
		var m map[string]any
		_ = jsonUnmarshal(rdapFixture, &m)
		return m, nil
	}
	t.Cleanup(func() { rdapFetch = oldRDAP })

	res := RunWhois(Options{Domain: "example.com", Logf: quietLogf})
	if res.Data["source"] != "rdap" {
		t.Errorf("source = %v", res.Data["source"])
	}
	w := res.Data["rdap"].(whoisRDAP)
	if w.Registrar != "RESERVED-IANA" || len(w.Nameservers) != 2 {
		t.Errorf("rdap = %+v", w)
	}
}

func TestWhoisTranco(t *testing.T) {
	oldRDAP, oldTranco := rdapFetch, trancoFetch
	rdapFetch = func(string, time.Duration) (map[string]any, error) { return nil, errors.New("down") }
	whoisQuery = (&whoisStub{err: errors.New("port 43 closed")}).query
	t.Cleanup(func() { rdapFetch, trancoFetch = oldRDAP, oldTranco })

	// rank 默认关：不出 tranco 字段（RDAP 正常路径）
	rdapOK := func(string, time.Duration) (map[string]any, error) {
		var m map[string]any
		_ = jsonUnmarshal(rdapFixture, &m)
		return m, nil
	}
	oldRDAP2 := rdapFetch
	rdapFetch = rdapOK
	res := RunWhois(Options{Domain: "example.com", Logf: quietLogf})
	if _, ok := res.Data["rank"]; ok {
		t.Error("--rank 关不应出 rank")
	}
	// rank 开 + 接口失败 → 静默跳过（rank 缺席不报错）
	trancoFetch = func(string, time.Duration) (map[string]any, error) { return nil, errors.New("tranco down") }
	res = RunWhois(Options{Domain: "example.com", Rank: true, Logf: quietLogf})
	if _, ok := res.Data["rank"]; ok {
		t.Error("tranco 失败应静默跳过")
	}
	// rank 开 + 成功 → rank 在场
	trancoFetch = func(string, time.Duration) (map[string]any, error) {
		return map[string]any{"rank": float64(12345), "domain": "example.com"}, nil
	}
	res = RunWhois(Options{Domain: "example.com", Rank: true, Logf: quietLogf})
	if res.Data["rank"] != float64(12345) {
		t.Errorf("rank = %v", res.Data["rank"])
	}
	t.Cleanup(func() { rdapFetch = oldRDAP2 })
}

func TestWhoisTimeoutSilent(t *testing.T) {
	oldRDAP, oldQuery := rdapFetch, whoisQuery
	rdapFetch = func(string, time.Duration) (map[string]any, error) {
		return nil, errors.New("context deadline exceeded")
	}
	whoisQuery = (&whoisStub{err: errors.New("i/o timeout")}).query
	t.Cleanup(func() { rdapFetch, whoisQuery = oldRDAP, oldQuery })

	res := RunWhois(Options{Domain: "example.com", Logf: quietLogf})
	if res.Error == "" {
		t.Error("RDAP+43 全不可达应置 Error（fail 事件，由聚合器保证不阻塞其余检查）")
	}
	if !strings.Contains(res.Error, "超时") && !strings.Contains(res.Error, "不可达") {
		t.Errorf("错误应含原因: %s", res.Error)
	}
}
