// mailsec.go — 邮件安全检查（报告 §5.3）：MX 服务商指纹 / SPF all 机制判定
// （include/redirect 最多展开 2 层防递归）/ DMARC p= 分档（pct 再分档）/
// DKIM selector 表试探 + 公钥位数解析（PEM + x509）。
// 只查 DNS（dnsClient 抽象，单测注入固定记录），不碰目标 80/443。
package baseline

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
)

// mxProviderFingerprints MX 目标后缀 → 服务商（webcheck mail-config.js 特征表
// 的可维护子集，顺序敏感：具体后缀在前、泛后缀在后，可扩）。
var mxProviderFingerprints = []struct{ suffix, vendor string }{
	{"mxbiz1.qq.com", "腾讯企业邮箱"},
	{"mxbiz2.qq.com", "腾讯企业邮箱"},
	{"mxhichina.com", "阿里云邮箱"},
	{"mxmail.netease.com", "网易邮箱"},
	{"qiye.163.com", "网易企业邮箱"},
	{"googlemail.com", "Google Workspace"},
	{"google.com", "Google Workspace"},
	{"protection.outlook.com", "Microsoft 365"},
	{"outlook.com", "Microsoft 365"},
	{"aliyun.com", "阿里云邮箱"},
	{"qq.com", "腾讯"},
	{"163.com", "网易"},
}

// mxVendor MX 目标主机 → 服务商指纹（命中即返回；未命中返回 ""）。
func mxVendor(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, f := range mxProviderFingerprints {
		if strings.HasSuffix(h, f.suffix) {
			return f.vendor
		}
	}
	return ""
}

// dkimSelectors 首版 selector 子集（mail-config.js DKIM_SELECTORS 17 个中取
// 常用 8 个，报告 §5.3「首版取其子集即可」）。
var dkimSelectors = []string{"google", "default", "selector1", "selector2", "k1", "s1", "s2", "dkim"}

// spfInfo SPF 记录解析结果。
type spfInfo struct {
	Record   string   // 原始记录（空 = 未发布）
	All      string   // "-all"/"~all"/"?all"/"+all"/""（未声明 all）
	Includes []string // include= 域列表（不含展开）
	Redirect string   // redirect= 目标（可空）
}

// parseSPF 解析 v=spf1 记录的机制字段。
func parseSPF(record string) spfInfo {
	info := spfInfo{Record: record}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=spf1") {
		return spfInfo{}
	}
	for _, f := range strings.Fields(record)[1:] {
		switch {
		case f == "-all" || f == "~all" || f == "?all" || f == "+all":
			info.All = f
		case strings.HasPrefix(f, "include:"):
			info.Includes = append(info.Includes, strings.TrimPrefix(f, "include:"))
		case strings.HasPrefix(f, "redirect="):
			info.Redirect = strings.TrimPrefix(f, "redirect=")
		}
	}
	return info
}

// spfAllVerdict all 机制 → (level, 结论)。报告 §5.3：-all 严 / ~all 软 /
// ?all 忽略 / +all 全放行判高危；缺失 all 记不声明。
func spfAllVerdict(all string) (string, string) {
	switch all {
	case "-all":
		return LevelOK, "SPF 严格（-all）"
	case "~all":
		return LevelWarn, "SPF 软失败（~all）"
	case "?all":
		return LevelInfo, "SPF all 忽略（?all）"
	case "+all":
		return LevelFail, "SPF +all 全放行（高危，任何主机可代发）"
	default:
		return LevelWarn, "SPF 未声明 all 机制"
	}
}

// spfExpandMaxDepth include/redirect 递归展开上限（§5.3 冷读统一为 2 层）。
const spfExpandMaxDepth = 2

// walkSPF 递归展开 include=/redirect= 指向域的 SPF 记录，depth ≤ 2、
// visited 防环、总条目封顶防滥用。out 收集「域 → 记录/失败原因」行。
func walkSPF(record string, depth int, visited map[string]bool, out *[]string) {
	if depth > spfExpandMaxDepth || len(*out) > 20 {
		return
	}
	var targets []string
	for _, f := range strings.Fields(record)[1:] {
		if strings.HasPrefix(f, "include:") {
			targets = append(targets, strings.TrimPrefix(f, "include:"))
		} else if strings.HasPrefix(f, "redirect=") {
			targets = append(targets, strings.TrimPrefix(f, "redirect="))
		}
	}
	for _, t := range targets {
		t = strings.TrimSuffix(strings.TrimSpace(t), ".")
		if t == "" || visited[t] {
			continue
		}
		visited[t] = true
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		txts, err := dns.LookupTXT(ctx, t)
		cancel()
		if err != nil {
			*out = append(*out, fmt.Sprintf("%s → 查询失败（%v）", t, err))
			continue
		}
		var sub string
		for _, r := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
				sub = r
				break
			}
		}
		if sub == "" {
			*out = append(*out, t+" → 无 SPF 记录")
			continue
		}
		*out = append(*out, fmt.Sprintf("%s → %s", t, sub))
		walkSPF(sub, depth+1, visited, out)
	}
}

var (
	reDmarcP   = regexp.MustCompile(`(?i)(?:^|;)\s*p\s*=\s*([a-z]+)`)
	reDmarcPct = regexp.MustCompile(`(?i)(?:^|;)\s*pct\s*=\s*(\d+)`)
)

// dmarcInfo DMARC 记录解析结果。
type dmarcInfo struct {
	Present bool
	Record  string
	P       string // none/quarantine/reject（空 = 未声明）
	Pct     int    // 默认 100
}

// parseDMARC 从 TXT 记录列表找 v=DMARC1 并解析 p=/pct=。
func parseDMARC(records []string) dmarcInfo {
	for _, r := range records {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			continue
		}
		di := dmarcInfo{Present: true, Record: r, Pct: 100}
		if m := reDmarcP.FindStringSubmatch(r); m != nil {
			di.P = strings.ToLower(m[1])
		}
		if m := reDmarcPct.FindStringSubmatch(r); m != nil {
			fmt.Sscanf(m[1], "%d", &di.Pct)
		}
		return di
	}
	return dmarcInfo{}
}

// dmarcVerdict DMARC 分档（§5.3）：无记录或 p=none 判可伪造；
// p=quarantine/reject 按 pct 再分档。
func dmarcVerdict(d dmarcInfo) (string, string) {
	if !d.Present {
		return LevelFail, "可伪造：未发布 DMARC 记录"
	}
	switch d.P {
	case "reject":
		if d.Pct < 100 {
			return LevelWarn, fmt.Sprintf("DMARC p=reject 但 pct=%d（部分生效）", d.Pct)
		}
		return LevelOK, "DMARC p=reject（拒绝伪造）"
	case "quarantine":
		if d.Pct < 100 {
			return LevelWarn, fmt.Sprintf("DMARC p=quarantine 但 pct=%d（部分生效）", d.Pct)
		}
		return LevelOK, "DMARC p=quarantine（隔离可疑件）"
	case "none":
		return LevelFail, "可伪造：DMARC p=none（只监控不处置）"
	default:
		return LevelWarn, "DMARC 未声明 p= 标签"
	}
}

var reDKIMPub = regexp.MustCompile(`(?i)(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=]*)`) // p= 空 = 公钥撤销

// dkimKeyBits 解析 DKIM p= 公钥位数：PEM 包裹 → x509.ParsePKIXPublicKey →
// RSA/ECDSA 取模长/曲线位数，ed25519 记 256。解析失败返回 (0, err)。
func dkimKeyBits(pubB64 string) (int, error) {
	if _, err := base64.StdEncoding.DecodeString(pubB64); err != nil {
		return 0, fmt.Errorf("公钥 base64 解码失败: %w", err)
	}
	// PEM body 用原始 base64 串按 64 字符换行（在 DER 字节上重编码会在
	// 非 3 倍数边界产生流中 padding "="，pem.Decode 必败——单测实测踩中）
	var sb strings.Builder
	sb.WriteString("-----BEGIN PUBLIC KEY-----\n")
	rest := pubB64
	for len(rest) > 0 {
		n := len(rest)
		if n > 64 {
			n = 64
		}
		sb.WriteString(rest[:n])
		sb.WriteString("\n")
		rest = rest[n:]
	}
	sb.WriteString("-----END PUBLIC KEY-----")
	blk, _ := pem.Decode([]byte(sb.String()))
	if blk == nil {
		return 0, fmt.Errorf("PEM 解码失败")
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return 0, fmt.Errorf("公钥解析失败: %w", err)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen(), nil
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize, nil
	case ed25519.PublicKey:
		return 256, nil
	default:
		return 0, fmt.Errorf("未知公钥类型 %T", key)
	}
}

// RunMailsec 邮件安全检查主流程。结论三档（§5.3，可伪造 > 策略宽松 > 正常）：
//   - 可伪造（fail）：无 DMARC 或 p=none；
//   - 策略宽松（warn）：SPF 含 +all（DMARC 在场时本档才可见，无 DMARC 已被上档覆盖）；
//   - 正常（ok）。
//
// MX/SPF/DMARC/DKIM 查询全部失败 → Result.Error（fail 事件，不阻塞聚合）。
func RunMailsec(o Options) Result {
	res := NewResult(CheckMailsec, o.Domain, "")
	d := o.Domain

	// MX + 服务商指纹
	mxErr := error(nil)
	mxRows := []map[string]any{}
	mxs, err := qDNS(func(ctx context.Context) ([]*netMX, error) { return dns.LookupMX(ctx, d) })
	if err != nil {
		mxErr = err
	}
	for _, m := range mxs {
		host := strings.TrimSuffix(m.Host, ".")
		row := map[string]any{"host": host, "pref": m.Pref}
		if v := mxVendor(host); v != "" {
			row["vendor"] = v
		}
		mxRows = append(mxRows, row)
	}

	// SPF（域 TXT）
	spfErr := error(nil)
	var spf spfInfo
	txts, err := qDNS(func(ctx context.Context) ([]string, error) { return dns.LookupTXT(ctx, d) })
	if err != nil {
		spfErr = err
	}
	for _, r := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
			spf = parseSPF(r)
			break
		}
	}
	var spfExpanded []string
	if spf.Record != "" {
		walkSPF(spf.Record, 1, map[string]bool{}, &spfExpanded)
	}

	// DMARC（_dmarc.<域名> TXT）
	dmErr := error(nil)
	var dmarc dmarcInfo
	dtxts, err := qDNS(func(ctx context.Context) ([]string, error) {
		return dns.LookupTXT(ctx, "_dmarc."+d)
	})
	if err != nil {
		dmErr = err
	}
	dmarc = parseDMARC(dtxts)

	// DKIM selector 试探
	dkimErrCount := 0
	dkimRows := []map[string]any{}
	for _, sel := range dkimSelectors {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
		recs, err := dns.LookupTXT(ctx, sel+"._domainkey."+d)
		cancel()
		if err != nil {
			dkimErrCount++
			continue
		}
		for _, r := range recs {
			m := reDKIMPub.FindStringSubmatch(r)
			if m == nil {
				continue
			}
			row := map[string]any{"selector": sel, "present": true}
			if m[1] == "" {
				row["note"] = "公钥已撤销（p= 空）"
			} else if bits, kerr := dkimKeyBits(m[1]); kerr == nil {
				row["bits"] = bits
				if bits < 1024 {
					row["note"] = fmt.Sprintf("公钥仅 %d 位（弱）", bits)
				}
			} else {
				row["note"] = "公钥解析失败：" + kerr.Error()
			}
			dkimRows = append(dkimRows, row)
			break
		}
	}

	// 全部 DNS 失败 → fail 事件（Error 字段），不编造空结果
	if isDNSFail(mxErr) && isDNSFail(spfErr) && isDNSFail(dmErr) && dkimErrCount == len(dkimSelectors) {
		res.Error = fmt.Sprintf("DNS 查询全部失败（MX/SPF/DMARC/DKIM 均不可达）: %v", firstErr(mxErr, spfErr, dmErr))
		res.Conclusion = Conclusion{Level: LevelFail, Text: "DNS 不可达，无法评估邮件安全"}
		return res
	}

	// 风险与结论
	spfLevel, spfText := LevelInfo, "未发布 SPF 记录"
	if spf.Record != "" {
		spfLevel, spfText = spfAllVerdict(spf.All)
	}
	dmLevel, dmText := dmarcVerdict(dmarc)
	switch spfLevel {
	case LevelFail:
		res.Risks = append(res.Risks, Risk{Level: LevelFail, Title: "SPF +all 全放行", Detail: spf.Record})
	case LevelWarn:
		res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: spfText, Detail: spf.Record})
	}
	if spf.Record == "" {
		res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "未发布 SPF 记录"})
	}
	if dmLevel == LevelFail {
		res.Risks = append(res.Risks, Risk{Level: LevelFail, Title: dmText})
	} else if dmLevel == LevelWarn {
		res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: dmText, Detail: dmarc.Record})
	}
	for _, row := range dkimRows {
		if note, _ := row["note"].(string); strings.Contains(note, "弱") {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: fmt.Sprintf("DKIM %v 公钥弱", row["selector"]), Detail: note})
		}
	}
	for _, row := range mxRows {
		if v, ok := row["vendor"].(string); ok {
			res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: fmt.Sprintf("MX 托管于 %s（%v）", v, row["host"])})
		}
	}

	// 结论三档：可伪造 > 策略宽松 > 正常（DMARC 部分生效 pct<100 归 warn 档，
	// §5.3「p=quarantine/reject 按 pct 再分档」）
	var vendors []string
	for _, row := range mxRows {
		if v, ok := row["vendor"].(string); ok && !containsStr(vendors, v) {
			vendors = append(vendors, v)
		}
	}
	prov := "未识别"
	if len(vendors) > 0 {
		prov = strings.Join(vendors, "/")
	}
	switch {
	case dmLevel == LevelFail:
		res.Conclusion = Conclusion{Level: LevelFail, Text: "可伪造（" + dmText + "；SPF: " + spfText + "）"}
	case spfLevel == LevelFail || spfLevel == LevelWarn:
		res.Conclusion = Conclusion{Level: LevelWarn, Text: "策略宽松（" + spfText + "；DMARC: " + dmText + "）"}
	case dmLevel == LevelWarn:
		res.Conclusion = Conclusion{Level: LevelWarn, Text: "DMARC 部分生效（" + dmText + "）"}
	default:
		res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf("正常（%s；%s；DKIM %d 条）", spfText, dmText, len(dkimRows))}
	}

	res.Data["mx"] = mxRows
	res.Data["spf"] = map[string]any{
		"record": spf.Record, "all": spf.All, "includes": spf.Includes,
		"redirect": spf.Redirect, "expanded": spfExpanded,
	}
	res.Data["dmarc"] = map[string]any{
		"present": dmarc.Present, "record": dmarc.Record, "p": dmarc.P, "pct": dmarc.Pct,
	}
	res.Data["dkim"] = dkimRows
	res.Data["provider"] = prov
	res.Data["summary"] = []string{
		fmt.Sprintf("MX %d 条（%s）", len(mxRows), prov),
		"SPF: " + spfText,
		"DMARC: " + dmText,
		fmt.Sprintf("DKIM 命中 %d/%d selector", len(dkimRows), len(dkimSelectors)),
	}
	return res
}

// qDNS 带单查询超时（3s）的 DNS 调用包装。
func qDNS[T any](fn func(ctx context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return fn(ctx)
}

// isDNSFail err 非 nil 即 DNS 失败（ NXDOMAIN/超时/拒连都算该源不可用）。
func isDNSFail(err error) bool { return err != nil }

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
