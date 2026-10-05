// geoasn.go — IP 归属/ASN 检查（报告 §5.8）：三源串行回退
//（ipwho.is → ip-api.com → get.geojs.io，以报告实读 location.js:20,40,60 为准），
// 统一响应 {country, region, isp, as, asname}（三家字段名分别映射）；
// 逐源 8s 超时、限速 1 QPS（连续外联调用之间 sleep 1s）；
// 「假 200 限频页」防御（body 含 quota/错误关键字判失败，沿用 icp.go 思路）；
// 多源分歧：两源成功且国家不一致 → 并列输出 + conflict 标记。
// 输入：用户直传 IP（Options.IPs），缺省对目标域做 A 解析（cap 5）。
// 免 key 公开源为模块本体（默认开，§5.0 分界）；geoFetch 可注入离线单测。
package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// geoSource 免 key 归属源（name 供字段映射分派；urlBase 拼接 ip）。
type geoSource struct {
	name    string
	urlBase string
}

// GeoSources 三源优先序（报告 §5.8 以 location.js 实读为准；可注入换靶）。
var GeoSources = []geoSource{
	{"ipwho.is", "https://ipwho.is/"},
	{"ip-api.com", "http://ip-api.com/json/"}, // 免 key 走 http（https 需付费 key）
	{"geojs", "https://get.geojs.io/v1/ip/geo.json?ip="},
}

// geoTimeout / geoRateInterval 逐源超时与限速间隔（§5.8：8s / 1 QPS）。
const (
	geoTimeout     = 8 * time.Second
	geoRateInterv1 = time.Second
)

// geoFetch 可注入（单测打桩）；生产走 netutil.Fetch。
var geoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: timeout})
	if !r.OK {
		return nil, fmt.Errorf("geo 请求失败: %s", r.Err)
	}
	if r.Status >= 400 {
		return nil, fmt.Errorf("geo HTTP %d", r.Status)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		return nil, fmt.Errorf("geo 响应非 JSON: %w", err)
	}
	return m, nil
}

// geoSleep 限速睡眠（可注入；默认真 sleep）。
var geoSleep = time.Sleep

// geoInfo 统一归属结构（§5.8：{country, region, isp/org, as, asname}）。
type geoInfo struct {
	Country string
	Region  string
	ISP     string
	AS      string
	ASName  string
}

// geoFake200 假 200 限频页防御：HTTP 200 但业务层报错/限额关键字 → 失败。
func geoFake200(m map[string]any) error {
	if st, ok := m["status"].(string); ok && st == "error" {
		msg, _ := m["message"].(string)
		return fmt.Errorf("源返回错误态（%s，多为限频）", msg)
	}
	if ok, exists := m["success"].(bool); exists && !ok {
		msg, _ := m["message"].(string)
		return fmt.Errorf("源返回失败态（%s，多为限频）", msg)
	}
	return nil
}

// parseGeoInfo 按源映射字段（三家 JSON 字段名不同，§5.8）。
func parseGeoInfo(source string, m map[string]any) geoInfo {
	g := geoInfo{}
	str := func(v any) string {
		if v == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	switch source {
	case "ipwho.is":
		g.Country = str(m["country"])
		g.Region = str(m["region"])
		if conn, ok := m["connection"].(map[string]any); ok {
			g.ISP = str(conn["isp"])
			g.ASName = str(conn["org"])
			if asn := str(conn["asn"]); asn != "" && asn != "0" {
				g.AS = "AS" + asn
			}
		}
	case "ip-api.com":
		g.Country = str(m["country"])
		g.Region = str(m["regionName"])
		g.ISP = str(m["isp"])
		g.AS = str(m["as"])
		g.ASName = str(m["asname"])
	case "geojs":
		g.Country = str(m["country"])
		g.Region = str(m["region"])
		g.ISP = str(m["organization_name"])
		if asn := str(m["asn"]); asn != "" && asn != "0" {
			g.AS = "AS" + asn
		}
		g.ASName = str(m["asn_organization"])
	}
	return g
}

// geoIPRow 单 IP 归属行（JSON 形态）。
type geoIPRow struct {
	IP       string   `json:"ip"`
	Source   string   `json:"source,omitempty"`
	Country  string   `json:"country,omitempty"`
	Region   string   `json:"region,omitempty"`
	ISP      string   `json:"isp,omitempty"`
	AS       string   `json:"as,omitempty"`
	ASName   string   `json:"asname,omitempty"`
	Conflict bool     `json:"conflict,omitempty"`
	Alt      *geoInfo `json:"alt,omitempty"` // 分歧第二源（并列输出）
	Note     string   `json:"note,omitempty"`
}

// geoMaxIPs 单次检查最多查询的 IP 数（控量）。
const geoMaxIPs = 5

// RunGeoASN IP 归属/ASN 检查主流程（§5.8）。
func RunGeoASN(o Options) Result {
	res := NewResult(CheckGeoASN, o.Domain, "")
	ips := o.IPs
	if len(ips) == 0 {
		// 缺省：对目标域解析 A 记录（复用 dns 抽象，cap 5）
		hosts, err := qDNS(func(ctx context.Context) ([]string, error) { return dns.LookupHost(ctx, o.Domain) })
		if err == nil {
			for _, h := range hosts {
				if net.ParseIP(h) != nil {
					ips = append(ips, h)
				}
				if len(ips) >= geoMaxIPs {
					break
				}
			}
		}
	}
	if len(ips) == 0 {
		res.Error = "无可用 IP（域名解析失败且未直传 IP）"
		res.Conclusion = Conclusion{Level: LevelFail, Text: "无归属查询对象"}
		return res
	}

	rows := []geoIPRow{}
	firstCall := true
	for _, ip := range ips {
		row := geoIPRow{IP: ip}
		var successes []geoSource
		var infos []geoInfo
		for i, src := range GeoSources {
			// 限速 1 QPS：每次外联调用（首个除外）前 sleep
			if !firstCall {
				geoSleep(geoRateInterv1)
			}
			firstCall = false
			u := src.urlBase
			if !strings.HasSuffix(u, "=") {
				u += url.PathEscape(ip)
			} else {
				u += url.QueryEscape(ip)
			}
			m, err := geoFetch(u, geoTimeout)
			if err == nil {
				err = geoFake200(m) // 假 200 防御（code=200 但 body 限频/错误）
			}
			if err != nil {
				continue
			}
			info := parseGeoInfo(src.name, m)
			if info.Country == "" && info.AS == "" {
				continue // 空壳响应按失败处理
			}
			successes = append(successes, src)
			infos = append(infos, info)
			// 首源成功 → 与次源交叉比对一次（分歧检测；§5.8 多源分歧）
			if i == 0 && len(successes) == 1 && len(GeoSources) > 1 {
				next := GeoSources[1]
				if !firstCall {
					geoSleep(geoRateInterv1)
				}
				u2 := next.urlBase
				if !strings.HasSuffix(u2, "=") {
					u2 += url.PathEscape(ip)
				} else {
					u2 += url.QueryEscape(ip)
				}
				if m2, err2 := geoFetch(u2, geoTimeout); err2 == nil && geoFake200(m2) == nil {
					if info2 := parseGeoInfo(next.name, m2); info2.Country != "" || info2.AS != "" {
						successes = append(successes, next)
						infos = append(infos, info2)
					}
				}
			}
			break // 已取到首源（+可选交叉源）
		}
		if len(infos) == 0 {
			row.Note = "三源均失败（超时/限频），未编造结果"
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: fmt.Sprintf("IP %s 归属查询失败", ip)})
		} else {
			fillGeoRow(&row, infos[0])
			row.Source = successes[0].name
			if len(infos) >= 2 && infos[0].Country != "" && infos[1].Country != "" && infos[0].Country != infos[1].Country {
				row.Conflict = true
				alt := infos[1]
				row.Alt = &alt
				res.Risks = append(res.Risks, Risk{Level: LevelWarn,
					Title: fmt.Sprintf("IP %s 归属分歧：%s（%s）vs %s（%s）", ip, successes[0].name, infos[0].Country, successes[1].name, infos[1].Country)})
			}
		}
		rows = append(rows, row)
	}

	okN := 0
	for _, r := range rows {
		if r.Source != "" {
			okN++
		}
	}
	if okN == 0 {
		res.Conclusion = Conclusion{Level: LevelFail, Text: "全部 IP 归属查询失败（多源均不可达/限频）"}
	} else {
		res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf("%d/%d 个 IP 取得归属（三源串行回退 + 1 QPS 限速）", okN, len(rows))}
	}
	res.Data["ips"] = rows
	summary := []string{}
	for _, r := range rows {
		if r.Source == "" {
			summary = append(summary, r.IP+": 查询失败")
			continue
		}
		line := fmt.Sprintf("%s: %s（%s，AS %s）", r.IP, r.Country, r.Source, orDash(r.AS))
		if r.Conflict {
			line += fmt.Sprintf(" ⚠ 与 %s 分歧（%s）", "次源", r.Alt.Country)
		}
		summary = append(summary, line)
	}
	res.Data["summary"] = summary
	return res
}

// fillGeoRow 统一结构 → 行字段。
func fillGeoRow(row *geoIPRow, g geoInfo) {
	row.Country, row.Region, row.ISP, row.AS, row.ASName = g.Country, g.Region, g.ISP, g.AS, g.ASName
}
