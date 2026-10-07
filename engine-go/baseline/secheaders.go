// secheaders.go — 安全响应头检查（报告 §5.1）：8 条安全头规则表驱动判定
// （HSTS 阈值 10886400 = webcheck hsts.js MIN_MAX_AGE preload 最低线）、
// Cookie 属性审计（Secure/HttpOnly/SameSite 任一缺失记不安全项）、
// WAF 特征表（firewall.js 三元组 header/子串/厂商 翻译 + 3 条国产占位）、
// 手动逐跳重定向链（上限 5 跳，落点过 HopPolicy——公网入口的 302 落私网拒绝）。
//
// 实现说明：取头走「不跟随手动逐跳循环」单通道（链、终响应头、Cookie 一并
// 取得，请求量小于报告设想的「跟随+不跟随」双请求；验收以逐跳可见与
// HopPolicy 拒绝为准，双通道属实现细节）。传输层复用 netutil.ProbeTransport，
// 探测 TLS 策略单点定义于 netutil（fetch.go 既有授权探测语义）。
package baseline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// secTransport 可注入传输层（单测打桩）；nil = netutil.ProbeTransport()。
var secTransport http.RoundTripper

// hopPolicyFor 可注入逐跳校验工厂（默认 netutil.HopPolicy(entry)）。
var hopPolicyFor = netutil.HopPolicy

// errPrivateHop 私网落点被拒的哨兵错误（打桩测试断言用）。
var errPrivateHop = errors.New("落点为私网/保留地址，已阻断")

// secMaxHops 逐跳上限（§5.1）。
const secMaxHops = 5

// hstsMinMaxAge HSTS max-age 达标线（webcheck hsts.js MIN_MAX_AGE=10886400，
// 报告 §5.1 冷读订正值）。
const hstsMinMaxAge = 10886400

var reMaxAge = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)

// secHeaderRow 单条安全头判定行。
type secHeaderRow struct {
	Name  string `json:"name"`
	State string `json:"state"` // ok / warn / missing
	Note  string `json:"note"`
}

// secRule 规则表条目（表驱动 = 单测逐条喂样例头）。
type secRule struct {
	Name   string
	Judge  func(v string) (state, note string)
	Absent string // 缺席结论文案
}

var secRules = []secRule{
	{Name: "Strict-Transport-Security", Judge: judgeHSTS, Absent: "未启用 HSTS（无 Strict-Transport-Security 头）"},
	{Name: "Content-Security-Policy", Judge: judgeCSP, Absent: "未设置 Content-Security-Policy（XSS 面无脚本白名单）"},
	{Name: "X-Frame-Options", Judge: judgeXFO, Absent: "未设置 X-Frame-Options（可被 iframe 嵌套，点击劫持面）"},
	{Name: "X-Content-Type-Options", Judge: judgeXCTO, Absent: "未设置 X-Content-Type-Options（MIME 嗅探面）"},
	{Name: "Referrer-Policy", Judge: judgeReferrer, Absent: "未设置 Referrer-Policy"},
	{Name: "Permissions-Policy", Judge: judgePlainOK, Absent: "未设置 Permissions-Policy"},
	{Name: "Cross-Origin-Opener-Policy", Judge: judgePlainOK, Absent: "未设置 Cross-Origin-Opener-Policy"},
	{Name: "Cross-Origin-Embedder-Policy", Judge: judgePlainOK, Absent: "未设置 Cross-Origin-Embedder-Policy"},
}

// judgeHSTS 三条件：max-age≥10886400、includeSubDomains、preload（对照 hsts.js）。
func judgeHSTS(v string) (string, string) {
	m := reMaxAge.FindStringSubmatch(v)
	var missing []string
	if m == nil {
		missing = append(missing, "无 max-age 指令")
	} else if n, _ := strconv.Atoi(m[1]); n < hstsMinMaxAge {
		missing = append(missing, "max-age="+m[1]+" 低于 "+strconv.Itoa(hstsMinMaxAge)+"（preload 最低线）")
	}
	if !strings.Contains(strings.ToLower(v), "includesubdomains") {
		missing = append(missing, "缺 includeSubDomains")
	}
	if !strings.Contains(strings.ToLower(v), "preload") {
		missing = append(missing, "缺 preload")
	}
	if len(missing) == 0 {
		return "ok", "max-age=" + m[1] + " + includeSubDomains + preload 齐备"
	}
	return "warn", "HSTS 不达标：" + strings.Join(missing, "；")
}

// judgeCSP 存在性 + unsafe-inline/unsafe-eval 备注。
func judgeCSP(v string) (string, string) {
	lv := strings.ToLower(v)
	var bad []string
	if strings.Contains(lv, "unsafe-inline") {
		bad = append(bad, "unsafe-inline")
	}
	if strings.Contains(lv, "unsafe-eval") {
		bad = append(bad, "unsafe-eval")
	}
	if len(bad) > 0 {
		return "warn", "CSP 含 " + strings.Join(bad, "/") + "（脚本约束形同虚设）"
	}
	return "ok", "已设置"
}

// judgeXFO 只认 DENY/SAMEORIGIN。
func judgeXFO(v string) (string, string) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DENY", "SAMEORIGIN":
		return "ok", v
	default:
		return "warn", "取值 " + v + " 非 DENY/SAMEORIGIN（ALLOW-FROM 已废弃）"
	}
}

// judgeXCTO 只认 nosniff。
func judgeXCTO(v string) (string, string) {
	if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
		return "ok", "nosniff"
	}
	return "warn", "取值 " + v + " 非 nosniff"
}

// judgeReferrer 存在即达标，unsafe-url 备注。
func judgeReferrer(v string) (string, string) {
	if strings.Contains(strings.ToLower(v), "unsafe-url") {
		return "warn", "取值含 unsafe-url（完整 URL 外泄）"
	}
	return "ok", v
}

// judgePlainOK 存在即达标（Permissions/COOP/COEP）。
func judgePlainOK(v string) (string, string) { return "ok", v }

// judgeHeaders 规则表判定（单测入口）。
func judgeHeaders(h http.Header) []secHeaderRow {
	rows := make([]secHeaderRow, 0, len(secRules))
	for _, r := range secRules {
		v := h.Get(r.Name)
		if v == "" {
			rows = append(rows, secHeaderRow{Name: r.Name, State: "missing", Note: r.Absent})
			continue
		}
		state, note := r.Judge(v)
		// 资源放大加固（终修轮）：note 里的头值截断——对抗轮实测 ≤1MB 头值
		// 全量复制进 note 致产物 2 倍放大（判定语义用原值，仅产物瘦身）。
		rows = append(rows, secHeaderRow{Name: r.Name, State: state, Note: clipText(note, 4096)})
	}
	return rows
}

// clipText 产物注记截断（字节级，UTF-8 劈尾巴时 json 序列化仍安全——
// 无效尾字节按 invalid rune 编码，解码端替换处理）。
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("…（截断，原长 %d 字节）", len(s))
}

// secCookieRow 单条 Cookie 审计行。
type secCookieRow struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"httponly"`
	SameSite string   `json:"samesite,omitempty"`
	Issues   []string `json:"issues"`
}

// sameSiteString http.SameSite（int 枚举）→ JSON 友好文案；0（未声明）回 ""。
func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return ""
}

// judgeCookies Cookie 属性审计：任一缺失记不安全项（§5.1）。
func judgeCookies(cookies []*http.Cookie) []secCookieRow {
	rows := []secCookieRow{}
	for _, c := range cookies {
		ss := sameSiteString(c.SameSite)
		row := secCookieRow{
			Name: c.Name, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: ss,
			Issues: []string{},
		}
		if !c.Secure {
			row.Issues = append(row.Issues, "缺 Secure")
		}
		if !c.HttpOnly {
			row.Issues = append(row.Issues, "缺 HttpOnly")
		}
		if ss == "" {
			row.Issues = append(row.Issues, "缺 SameSite")
		}
		rows = append(rows, row)
	}
	return rows
}

// wafSignature WAF/CDN 特征三元组（firewall.js WAF_SIGNATURES 翻译；
// contains 空 = 头存在即命中）。
type wafSignature struct {
	header   string
	contains string
	vendor   string
}

// wafSignatures 特征表。国产三条为占位特征，待实战采样校准（§5.1）。
var wafSignatures = []wafSignature{
	{"server", "cloudflare", "Cloudflare"},
	{"cf-ray", "", "Cloudflare"},
	{"x-sucuri-id", "", "Sucuri"},
	{"x-sucuri-cache", "", "Sucuri"},
	{"x-cdn", "incapsula", "Imperva Incapsula"},
	{"x-iinfo", "", "Imperva Incapsula"},
	{"x-akamai-transformed", "", "Akamai"},
	{"server", "akamai", "Akamai"},
	{"x-vercel-id", "", "Vercel"},
	{"x-amz-cf-id", "", "AWS CloudFront"},
	{"x-ar-atime", "", "AZION"},
	// ── 国产占位（待实战采样校准）──
	{"x-webber-rasp", "", "WebberRASP"},
	{"server", "vsb", "博达 VSB 站群"},
	{"x-ws-request-id", "", "网宿 CDN"},
}

// matchWAF 特征表命中厂商（按表序去重）。
func matchWAF(h http.Header) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, sig := range wafSignatures {
		if seen[sig.vendor] {
			continue
		}
		v := h.Get(sig.header)
		if v == "" {
			continue
		}
		if sig.contains == "" || strings.Contains(strings.ToLower(v), sig.contains) {
			seen[sig.vendor] = true
			out = append(out, sig.vendor)
		}
	}
	return out
}

// secHop 逐跳记录。
type secHop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	Blocked  bool   `json:"blocked,omitempty"`
	Note     string `json:"note,omitempty"`
}

// resolveRef 相对/绝对 Location 解析为绝对 URL。
func resolveRef(base, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ref
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return bu.ResolveReference(ru).String()
}

// RunSecHeaders 安全响应头检查主流程（§5.1）。
func RunSecHeaders(o Options) Result {
	// 第一步「取消能力注入」连带件：本文件 http.Client 是引擎唯一裸 client，
	// 请求随 Options.Ctx 挂载取消（nil = Background，语义不变）
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	res := NewResult(CheckSecHeaders, o.Domain, o.URL)
	entry, err := baseEntry(o)
	if err != nil {
		res.Error = "入口 URL 非法：" + err.Error()
		res.Conclusion = Conclusion{Level: LevelFail, Text: "入口不可达校验未通过"}
		return res
	}
	res.URL = entry
	hop := hopPolicyFor(entry)
	client := &http.Client{Timeout: 15 * time.Second}
	if secTransport != nil {
		client.Transport = secTransport
	} else {
		client.Transport = netutil.ProbeTransport() // 探测 TLS 策略单点在 netutil
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // 手动逐跳（上限 5），落点过 HopPolicy
	}

	hops := []secHop{}
	cookiesAll := []*http.Cookie{}
	var finalHeader http.Header
	wafSeen := map[string]bool{}
	var wafVendors []string
	u := entry
	for i := 0; i < secMaxHops; i++ {
		req, rerr := http.NewRequest(http.MethodGet, u, nil)
		if rerr != nil {
			hops = append(hops, secHop{URL: u, Note: "请求构造失败: " + rerr.Error()})
			break
		}
		req.Header.Set("User-Agent", netutil.DefaultUA)
		req = req.WithContext(ctx) // 裸 client 取消贯通（第一步连带件）
		resp, derr := client.Do(req)
		if derr != nil {
			hops = append(hops, secHop{URL: u, Note: "请求失败: " + derr.Error()})
			break
		}
		rec := secHop{URL: u, Status: resp.StatusCode}
		cookiesAll = append(cookiesAll, resp.Cookies()...)
		for _, v := range matchWAF(resp.Header) {
			if !wafSeen[v] {
				wafSeen[v] = true
				wafVendors = append(wafVendors, v)
			}
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			rec.Location = loc
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if loc == "" {
				rec.Note = "30x 无 Location，链中止"
				hops = append(hops, rec)
				break
			}
			next := resolveRef(u, loc)
			if herr := hop(next); herr != nil {
				rec.Blocked = true
				rec.Note = "落点被边界校验拒绝：" + herr.Error()
				hops = append(hops, rec)
				break
			}
			hops = append(hops, rec)
			u = next
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		finalHeader = resp.Header
		rec.Note = "终响应"
		hops = append(hops, rec)
		break
	}
	res.Data["hops"] = hops

	// F2（终修轮）：blocked-hop 风险收集提前到 finalHeader==nil 早退之前——
	// 被拦 hop 必 break → finalHeader 恒 nil → 此前尾部风险循环是死代码，
	// 用户只见笼统「响应链未走通」，看不到「落点被边界校验拒绝」这一真实风险。
	for _, hp := range hops {
		if hp.Blocked {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "重定向落点被边界校验拒绝", Detail: hp.URL + " → " + hp.Location})
		}
	}

	if finalHeader == nil {
		res.Error = "未能取得终响应（重定向链中断/被拒/连接失败），详见 hops"
		res.Conclusion = Conclusion{Level: LevelFail, Text: "响应链未走通"}
		return res
	}

	// 规则表判定 + Cookie 审计 + WAF
	headerRows := judgeHeaders(finalHeader)
	missing, warns := 0, 0
	for _, r := range headerRows {
		switch r.State {
		case "missing":
			missing++
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: r.Note})
		case "warn":
			warns++
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: r.Name + "：" + r.Note})
		}
	}
	cookieRows := judgeCookies(cookiesAll)
	insecure := 0
	for _, c := range cookieRows {
		if len(c.Issues) > 0 {
			insecure++
			res.Risks = append(res.Risks, Risk{Level: LevelWarn,
				Title: "Cookie " + c.Name + " 属性不安全", Detail: strings.Join(c.Issues, "、")})
		}
	}
	for _, v := range wafVendors {
		res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: "疑似 WAF/CDN：" + v, Detail: "指纹特征命中，不代表防护有效"})
	}

	switch {
	case missing == 0 && insecure == 0 && warns == 0:
		res.Conclusion = Conclusion{Level: LevelOK, Text: "8 项安全头齐备，Cookie 无不安全项"}
	default:
		res.Conclusion = Conclusion{Level: LevelWarn, Text: fmt.Sprintf(
			"缺失 %d 个安全头（警告 %d 项），%d 条 Cookie 属性不安全", missing, warns, insecure)}
	}
	res.Data["entry"] = entry
	res.Data["headers"] = headerRows
	res.Data["cookies"] = cookieRows
	res.Data["waf"] = wafVendors
	res.Data["missing_count"] = missing
	res.Data["insecure_cookies"] = insecure
	res.Data["summary"] = []string{
		fmt.Sprintf("安全头 ok %d / 警告 %d / 缺失 %d", 8-missing-warns, warns, missing),
		fmt.Sprintf("Cookie %d 条（不安全 %d 条）", len(cookieRows), insecure),
	}
	if len(wafVendors) > 0 {
		res.Data["summary"] = append(res.Data["summary"].([]string), "WAF 疑似: "+strings.Join(wafVendors, ", "))
	}
	return res
}
