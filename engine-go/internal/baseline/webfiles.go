// webfiles.go — 网站文件检查（报告 §5.2）：robots.txt（Disallow/Allow/Sitemap，
// 非空 Disallow 回喂 paths_extra.txt）、sitemap.xml（encoding/xml 解析 <loc>，
// 解析前逐 token 拒 DOCTYPE/ENTITY——不可信 XML 双保险）、
// .well-known/security.txt 字段抽取、首页 og meta/<title>/<a href> 域名归类
//（同站 / 子域候选 / 外链；子域候选回喂 subdomain 候选集）。
// 全程只 GET 目标站自身，零第三方外联。
package baseline

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

var (
	reHTMLTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// og meta 两种属性序：property 在前 / content 在前
	reOgPropFirst = regexp.MustCompile(`(?is)<meta[^>]+property=["']og:([^"']+)["'][^>]*content=["']([^"']*)["']`)
	reOgContFirst = regexp.MustCompile(`(?is)<meta[^>]+content=["']([^"']*)["'][^>]+property=["']og:([^"']+)["']`)
	reAHref       = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"']+)["']`)
)

// parseRobots 逐行抽 User-agent 段的 Disallow/Allow 与任意位置的 Sitemap 行。
func parseRobots(text string) (disallow, allow, sitemaps []string) {
	disallow, allow, sitemaps = []string{}, []string{}, []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "disallow":
			if val != "" { // 空Disallow=全允许，不进补充字典
				disallow = append(disallow, val)
			}
		case "allow":
			if val != "" {
				allow = append(allow, val)
			}
		case "sitemap":
			if val != "" {
				sitemaps = append(sitemaps, val)
			}
		}
	}
	return disallow, allow, sitemaps
}

// parseSitemap encoding/xml 逐 token 解析 <loc>；遇 DOCTYPE/ENTITY 指令立即
// 中止（不可信 XML：encoding/xml 默认不展开外部实体，显式拒 DTD 做双保险，
// §5.2 安全约束）。
func parseSitemap(xmlText string) ([]string, error) {
	dec := xml.NewDecoder(strings.NewReader(xmlText))
	dec.Strict = true
	locs := []string{}
	inLoc := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sitemap 解析失败: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			up := strings.ToUpper(string(t))
			if strings.Contains(up, "DOCTYPE") || strings.Contains(up, "ENTITY") {
				return nil, fmt.Errorf("sitemap 含 DOCTYPE/ENTITY 指令，已拒绝解析（不可信 XML）")
			}
		case xml.StartElement:
			if t.Name.Local == "loc" {
				inLoc = true
			}
		case xml.CharData:
			if inLoc {
				if s := strings.TrimSpace(string(t)); s != "" {
					locs = append(locs, s)
				}
			}
		case xml.EndElement:
			if t.Name.Local == "loc" {
				inLoc = false
			}
		}
	}
	return locs, nil
}

// parseSecurityTxt 抽 Contact/Encryption/Policy/Preferred-Languages 字段
//（键小写；# 注释行跳过）。
func parseSecurityTxt(text string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		switch k {
		case "contact", "encryption", "policy", "preferred-languages":
			if _, dup := fields[k]; !dup {
				fields[k] = strings.TrimSpace(v)
			}
		}
	}
	return fields
}

// parseHome 抽 <title>、og:* meta（两种属性序）、<a href> 列表。
func parseHome(body string) (title string, og map[string]string, hrefs []string) {
	og = map[string]string{}
	if m := reHTMLTitle.FindStringSubmatch(body); m != nil {
		title = strings.TrimSpace(m[1])
	}
	for _, m := range reOgPropFirst.FindAllStringSubmatch(body, -1) {
		og["og:"+m[1]] = strings.TrimSpace(m[2])
	}
	for _, m := range reOgContFirst.FindAllStringSubmatch(body, -1) {
		if _, dup := og["og:"+m[2]]; !dup { // property 在前序优先
			og["og:"+m[2]] = strings.TrimSpace(m[1])
		}
	}
	for _, m := range reAHref.FindAllStringSubmatch(body, -1) {
		hrefs = append(hrefs, strings.TrimSpace(m[1]))
	}
	return title, og, hrefs
}

// classifyHrefs href 域名归类（§5.2）：相对/同 host → 同站；host==domain 或
// www.domain 或 *.domain 后缀 → 子域候选；其余有 host → 外链。
// javascript:/mailto:/锚点跳过。domain 为空时以入口 host 归类。
func classifyHrefs(hrefs []string, entryURL, domain string) (same, subCandidates, external []string) {
	same, subCandidates, external = []string{}, []string{}, []string{}
	base, _ := url.Parse(entryURL)
	siteHost := ""
	if base != nil {
		siteHost = strings.ToLower(base.Hostname())
	}
	if domain == "" {
		domain = siteHost
	}
	domain = strings.ToLower(domain)
	for _, h := range hrefs {
		lh := strings.ToLower(h)
		if strings.HasPrefix(lh, "javascript:") || strings.HasPrefix(lh, "mailto:") ||
			strings.HasPrefix(lh, "tel:") || h == "" || strings.HasPrefix(h, "#") {
			continue
		}
		u, err := url.Parse(h)
		if err != nil {
			continue
		}
		if base != nil && u.Scheme == "" && u.Host == "" { // 相对引用
			same = append(same, h)
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			same = append(same, h)
			continue
		}
		switch {
		case host == domain || host == "www."+domain:
			same = append(same, host)
		case strings.HasSuffix(host, "."+domain):
			subCandidates = append(subCandidates, host)
		default:
			external = append(external, host)
		}
	}
	return same, subCandidates, external
}

// RunWebfiles 网站文件检查主流程（§5.2）。
func RunWebfiles(o Options) Result {
	res := NewResult(CheckWebfiles, o.Domain, o.URL)
	entry, err := baseEntry(o)
	if err != nil {
		res.Error = "入口 URL 非法：" + err.Error()
		res.Conclusion = Conclusion{Level: LevelFail, Text: "入口不可达校验未通过"}
		return res
	}
	res.URL = entry
	base := strings.TrimRight(entry, "/")
	hop := netutil.HopPolicy(entry)
	get := func(u string) netutil.Result {
		return netutil.Fetch(u, netutil.FetchOpt{Timeout: defHTTPTimeout, Follow: true, HopCheck: hop})
	}
	isTextOK := func(r netutil.Result) bool { return r.OK && r.Status == 200 && r.Err == "" }

	// robots.txt
	robotsFound := false
	var disallow, allow, robotSitemaps []string
	if r := get(base + "/robots.txt"); isTextOK(r) {
		disallow, allow, robotSitemaps = parseRobots(r.Body)
		robotsFound = true
	}

	// sitemap：robots Sitemap 行两步取法，无则直试 /sitemap.xml
	sitemapSources := append([]string{}, robotSitemaps...)
	if len(sitemapSources) == 0 {
		sitemapSources = []string{base + "/sitemap.xml"}
	}
	sitemapURLs := []string{}
	sitemapNotes := []string{}
	for _, src := range sitemapSources {
		if len(sitemapURLs) > 500 {
			break
		}
		r := get(src)
		if !isTextOK(r) {
			sitemapNotes = append(sitemapNotes, src+" → 获取失败")
			continue
		}
		locs, err := parseSitemap(r.Body)
		if err != nil {
			sitemapNotes = append(sitemapNotes, fmt.Sprintf("%s → %v", src, err))
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "sitemap 拒绝解析", Detail: err.Error()})
			continue
		}
		sitemapURLs = append(sitemapURLs, locs...)
	}
	// 验收：paths_extra.txt（非空 Disallow 条目回喂 paths 字典，§5.2 管线入口）
	if len(disallow) > 0 {
		if _, err := netutil.SafeWrite(o.Out, "paths_extra.txt", strings.Join(disallow, "\n")); err != nil {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "paths_extra.txt 写盘失败", Detail: err.Error()})
		}
	}

	// security.txt
	secFound := false
	secFields := map[string]string{}
	if r := get(base + "/.well-known/security.txt"); isTextOK(r) {
		secFields = parseSecurityTxt(r.Body)
		secFound = len(secFields) > 0
	}

	// 首页
	homeFound := false
	title := ""
	og := map[string]string{}
	var hrefs []string
	if r := get(base + "/"); isTextOK(r) {
		title, og, hrefs = parseHome(r.Body)
		homeFound = title != "" || len(og) > 0 || len(hrefs) > 0
	}
	same, subCandidates, external := classifyHrefs(hrefs, entry, o.Domain)

	// 风险与结论
	if robotsFound && len(disallow) > 0 {
		res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: "robots.txt 泄露后台/敏感路径线索",
			Detail: "Disallow " + strings.Join(disallow, " ") + "（线索≠漏洞，需人工复核）"})
	}
	if secFound {
		res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: "security.txt 在场",
			Detail: "Contact " + secFields["contact"]})
	}
	if len(subCandidates) > 0 {
		res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: fmt.Sprintf("首页链接发现 %d 个子域候选", len(subCandidates)),
			Detail: strings.Join(subCandidates, ", ")})
	}
	level := LevelWarn
	summary := []string{}
	if !robotsFound && len(sitemapURLs) == 0 && !secFound && !homeFound {
		level = LevelWarn
		res.Conclusion = Conclusion{Level: LevelWarn, Text: "robots/sitemap/security.txt/首页均未取得（站点不可达或全空）"}
	} else {
		res.Conclusion = Conclusion{Level: level, Text: fmt.Sprintf(
			"robots %v（%d 条 Disallow）· sitemap %d loc · security.txt %v · 首页 %v（子域候选 %d，外链 %d）",
			robotsFound, len(disallow), len(sitemapURLs), secFound, homeFound, len(subCandidates), len(external))}
		summary = append(summary,
			fmt.Sprintf("robots.txt: %v（Disallow %d / Allow %d / Sitemap %d）", robotsFound, len(disallow), len(allow), len(robotSitemaps)),
			fmt.Sprintf("sitemap: %d loc（源 %d 个）", len(sitemapURLs), len(sitemapSources)),
			fmt.Sprintf("security.txt: %v", secFound),
			fmt.Sprintf("首页: %v（title=%q，og %d 项）", homeFound, title, len(og)),
			fmt.Sprintf("链接归类: 同站 %d / 子域候选 %d / 外链 %d", len(same), len(subCandidates), len(external)),
		)
	}

	res.Data["robots"] = map[string]any{
		"found": robotsFound, "disallow": disallow, "allow": allow,
		"sitemaps": robotSitemaps, "disallow_count": len(disallow),
	}
	res.Data["sitemap"] = map[string]any{
		"urls": sitemapURLs, "sources": sitemapSources, "notes": sitemapNotes,
	}
	res.Data["security_txt"] = map[string]any{"found": secFound, "fields": secFields}
	res.Data["home"] = map[string]any{"found": homeFound, "title": title, "og": og}
	res.Data["domains"] = map[string]any{
		"same": same, "subdomain_candidates": subCandidates, "external": external,
	}
	res.Data["summary"] = summary
	return res
}

// defHTTPTimeout 单请求超时（§5.2 页面抓取，12s 与 netutil.Fetch 默认一致）。
const defHTTPTimeout = 12 * 1e9 // time.Duration 纳秒（12s）
