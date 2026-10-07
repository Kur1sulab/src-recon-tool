// whois.go — WHOIS 注册信息检查（报告 §5.7）：RDAP 优先（rdap.org 免 key，
// 302 跟随到注册局 RDAP，encoding/json 解析 events/entities/nameservers/status，
// 字段缺失置空不编造）；43 端口回退（whois.iana.org → 注册局 → 注册商两级
// referral 链，正则抽 Registrar/Creation/Expiry/Name Server，首版覆盖 .com/.net
// Verisign 文本与 .cn CNNIC 文本，其余输出原文截断+标「未结构化」）。
// tranco 排名为附加字段（--rank 默认关，失败静默，§5.0 外联最小化）。
// 与 icp 组成资产归属双通道：icp 管国内备案、whois 管国际注册。
package baseline

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// RDAPBase / TrancoBase 免 key 公开源（可注入换靶）。
var (
	RDAPBase   = "https://rdap.org/domain/"
	TrancoBase = "https://tranco-list.eu/api/ranks/domain/"
)

// rdapFetch 可注入（单测打桩）；生产走 netutil.Fetch（跟随 302）。
var rdapFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: timeout})
	if !r.OK {
		return nil, fmt.Errorf("RDAP 请求失败: %s", r.Err)
	}
	if r.Status >= 400 {
		return nil, fmt.Errorf("RDAP HTTP %d", r.Status)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		return nil, fmt.Errorf("RDAP 响应非 JSON: %w", err)
	}
	return m, nil
}

// trancoFetch 可注入；生产走 netutil.Fetch（失败静默）。
var trancoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: timeout})
	if !r.OK || r.Status >= 400 {
		return nil, fmt.Errorf("tranco HTTP %d err=%s", r.Status, r.Err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// whoisQuery 43 端口文本查询（可注入单测）；生产 net.DialTimeout + 写域名\r\n
// + 读到关闭。
var whoisQuery = func(server, query string, timeout time.Duration) (string, error) {
	server = strings.TrimPrefix(strings.TrimPrefix(server, "whois://"), "http://")
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	buf := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil || len(buf) > 1<<20 {
			break
		}
	}
	return string(buf), nil
}

// whoisRDAP RDAP 解析结果（字段缺失置空不编造）。
type whoisRDAP struct {
	Registrar   string            `json:"registrar,omitempty"`
	Events      map[string]string `json:"events,omitempty"` // registration/expiration/last changed
	Nameservers []string          `json:"nameservers,omitempty"`
	Status      []string          `json:"status,omitempty"`
}

// parseRDAP RDAP JSON → 结构化（events 按 eventAction 归集；registrar 取
// roles 含 registrar 实体的 vcard fn；nameservers ldhName 小写）。
func parseRDAP(m map[string]any) whoisRDAP {
	w := whoisRDAP{Events: map[string]string{}}
	if events, ok := m["events"].([]any); ok {
		for _, e := range events {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			action, _ := em["eventAction"].(string)
			date, _ := em["eventDate"].(string)
			if action != "" && date != "" {
				w.Events[action] = date
			}
		}
	}
	if ents, ok := m["entities"].([]any); ok {
		for _, e := range ents {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			isRegistrar := false
			if roles, ok := em["roles"].([]any); ok {
				for _, r := range roles {
					if s, ok := r.(string); ok && s == "registrar" {
						isRegistrar = true
					}
				}
			}
			if !isRegistrar {
				continue
			}
			if va, ok := em["vcardArray"].([]any); ok && len(va) > 1 {
				if rows, ok := va[1].([]any); ok {
					for _, row := range rows {
						rm, ok := row.([]any)
						if !ok || len(rm) < 4 {
							continue
						}
						if s, ok := rm[0].(string); ok && s == "fn" {
							if name, ok := rm[3].(string); ok {
								w.Registrar = name
							}
						}
					}
				}
			}
		}
	}
	if ns, ok := m["nameservers"].([]any); ok {
		for _, n := range ns {
			nm, ok := n.(map[string]any)
			if !ok {
				continue
			}
			if h, ok := nm["ldhName"].(string); ok && h != "" {
				w.Nameservers = append(w.Nameservers, strings.ToLower(h))
			}
		}
	}
	if st, ok := m["status"].([]any); ok {
		for _, s := range st {
			if v, ok := s.(string); ok {
				w.Status = append(w.Status, v)
			}
		}
	}
	return w
}

// whoisText 43 端口文本抽取结果。
type whoisText struct {
	Registrar   string   `json:"registrar,omitempty"`
	Creation    string   `json:"creation,omitempty"`
	Expiry      string   `json:"expiry,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
	Structured  bool     `json:"structured"` // 抽到任一字段 = 结构化成功
}

var (
	reWhoisRegistrar = regexp.MustCompile(`(?im)^\s*registrar(?:名称)?[:：]\s*(.+)$`)
	reWhoisCreated   = regexp.MustCompile(`(?im)^\s*(?:creation date|created on|registration time|注册时间)[:：]\s*(.+)$`)
	reWhoisExpiry    = regexp.MustCompile(`(?im)^\s*(?:registry expiry date|expiry date|expiration time|expire date|到期时间|过期时间)[:：]\s*(.+)$`)
	reWhoisNS        = regexp.MustCompile(`(?im)^\s*(?:name server|nserver|域名服务器)[:：]\s*(\S+)$`)
)

// parseWhoisText 43 端口文本正则抽取（.com/.net Verisign 与 .cn CNNIC 覆盖；
// 抽不到任一字段 = 未结构化，输出原文截断）。
func parseWhoisText(text string) whoisText {
	var w whoisText
	if m := reWhoisRegistrar.FindStringSubmatch(text); m != nil {
		w.Registrar = strings.TrimSpace(m[1])
	}
	if m := reWhoisCreated.FindStringSubmatch(text); m != nil {
		w.Creation = strings.TrimSpace(m[1])
	}
	if m := reWhoisExpiry.FindStringSubmatch(text); m != nil {
		w.Expiry = strings.TrimSpace(m[1])
	}
	for _, m := range reWhoisNS.FindAllStringSubmatch(text, -1) {
		w.NameServers = append(w.NameServers, strings.TrimSpace(m[1]))
	}
	w.Structured = w.Registrar != "" || w.Creation != "" || w.Expiry != "" || len(w.NameServers) > 0
	return w
}

var reReferral = regexp.MustCompile(`(?im)^\s*(?:refer|referralserver|registrar whois server)[:：]\s*(\S+)\s*$`)

// extractReferral 抽 43 文本里的下一跳 WHOIS 服务器（IANA refer / 注册局
// Registrar WHOIS Server / ReferralServer；剥 whois:// 前缀）。经
// referralHostOK 形状闸——不合格返回 ""（referral 循环终止）。
func extractReferral(text string) string {
	m := reReferral.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	next := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(m[1]), "whois://"), "http://")
	if !referralHostOK(next) {
		return ""
	}
	return next
}

// referralHostOK referral 下一跳主机形状闸（终修轮 F3·审计）：43 端口回退链
// 的下一跳取自上一跳响应文本，恶意注册局/注册商文本可驱使工具向任意主机:43
// 拨号——至少锁死主机形状：仅域名字符集（字母/数字/点/连字符）、1-253 长度、
// 不以点/连字符开头结尾、至少含一个点（剥 scheme/端口/路径后残留即拒）。
func referralHostOK(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	if strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") ||
		strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	return strings.Contains(h, ".")
}

// whoisMaxHops referral 链上限（IANA→注册局→注册商 = 2 跳，共 3 查询）。
const whoisMaxHops = 2

// whoisTimeoutRDAP / whoisTimeout43 单请求超时。
const (
	whoisTimeoutRDAP = 20 * time.Second
	whoisTimeout43   = 10 * time.Second
)

// RunWhois WHOIS 注册信息检查主流程（§5.7）。
func RunWhois(o Options) Result {
	res := NewResult(CheckWhois, o.Domain, "")
	d := o.Domain

	// 1) RDAP 优先
	m, err := rdapFetch(RDAPBase+d, whoisTimeoutRDAP)
	if err == nil {
		w := parseRDAP(m)
		res.Data["source"] = "rdap"
		res.Data["rdap"] = w
		if exp, ok := w.Events["expiration"]; ok {
			res.Data["expiration"] = exp
			if t, perr := time.Parse(time.RFC3339, exp); perr == nil {
				days := int(time.Until(t).Hours() / 24)
				if days < 0 {
					res.Risks = append(res.Risks, Risk{Level: LevelFail, Title: fmt.Sprintf("域名已过期 %d 天", -days), Detail: exp})
				} else if days < 30 {
					res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: fmt.Sprintf("域名 %d 天后到期", days), Detail: exp})
				}
			}
		}
		res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf("RDAP 注册信息（注册商 %s）", orDash(w.Registrar))}
	} else {
		// 2) 43 端口回退：IANA → 注册局 → 注册商两级 referral
		text, qerr := whoisQuery("whois.iana.org", d, whoisTimeout43)
		if qerr != nil {
			res.Error = fmt.Sprintf("RDAP（%v）与 43 端口（%v）均不可达", err, qerr)
			res.Conclusion = Conclusion{Level: LevelFail, Text: "WHOIS 源超时/不可达"}
			return res
		}
		hop, finalText := 0, text
		for hop < whoisMaxHops {
			next := extractReferral(finalText)
			if next == "" || strings.EqualFold(next, "whois.iana.org") {
				break
			}
			t2, qerr := whoisQuery(next, d, whoisTimeout43)
			if qerr != nil {
				break
			}
			finalText, hop = t2, hop+1
		}
		w := parseWhoisText(finalText)
		res.Data["source"] = "whois43"
		if w.Structured {
			res.Data["whois"] = w
			res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf("43 端口注册信息（%d 级 referral，注册商 %s）", hop, orDash(w.Registrar))}
		} else {
			// 未结构化：原文截断留证，不编造字段
			raw := finalText
			lines := strings.Split(raw, "\n")
			if len(lines) > 40 {
				lines = lines[:40]
				raw = strings.Join(lines, "\n") + "\n…（截断）"
			}
			res.Data["whois"] = whoisText{}
			res.Data["raw_truncated"] = raw
			res.Data["unstructured"] = true
			res.Conclusion = Conclusion{Level: LevelInfo, Text: "43 端口响应未结构化（TLD 暂不支持解析），原文已截断留证"}
		}
	}

	// 3) tranco 附加（--rank 默认关；失败静默，§5.7）
	if o.Rank {
		if tm, terr := trancoFetch(TrancoBase+d, 10*time.Second); terr == nil {
			if rank, ok := tm["rank"]; ok {
				res.Data["rank"] = rank
			}
		}
	}
	return res
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
