// archives.go — 历史归档检查（报告 §5.4）：Wayback CDX 接口分页拉取
// （showNumPages → 逐页，5 万行上限 + 总超时 + 3 次退避重试）、URL 规范化去重
// （小写 host、去 fragment）、敏感分流（扩展名 + 路径关键词 → 高危清单）、
// 高危清单与 paths 字典交叉标注（dup/new，只出清单不自动探测）。
// CDX 是免 key 公开源（模块本体默认开，§5.0 分界）；cdxFetch 可注入离线单测。
package baseline

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/paths"
)

// CDXBase Wayback CDX 接口（可注入换靶）。
var CDXBase = "https://web.archive.org/cdx/search/cdx"

// cdxFetch 可注入（单测打桩）；生产走 netutil.Fetch。
var cdxFetch = func(rawURL string, timeout time.Duration) (string, error) {
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: timeout})
	if !r.OK {
		return "", fmt.Errorf("CDX 请求失败: %s", r.Err)
	}
	if r.Status >= 400 {
		return "", fmt.Errorf("CDX HTTP %d", r.Status)
	}
	return r.Body, nil
}

// retrySleepCDX 退避重试间隔（可注入；对齐 icp/reverse 的降级写法）。
var retrySleepCDX = time.Sleep

const (
	cdxMaxLines = 50000 // 行数上限（FinalRecon 5 万条经验，§5.4）
	cdxMaxPages = 100   // 分页数上限（防超大站拖爆总预算）
	cdxTimeout  = 30 * time.Second
	cdxRetries  = 3
)

// cdxRow CDX 行（fl=original,timestamp,mimetype,statuscode）。
type cdxRow struct {
	Original   string `json:"original"`
	Timestamp  string `json:"timestamp,omitempty"`
	Mimetype   string `json:"mimetype,omitempty"`
	Statuscode string `json:"statuscode,omitempty"`
}

// parseCDXLine 解析一行 CDX 文本（空格分隔；字段缺失容忍）。
func parseCDXLine(line string) (cdxRow, bool) {
	f := strings.Fields(line)
	if len(f) < 1 || f[0] == "" {
		return cdxRow{}, false
	}
	r := cdxRow{Original: f[0]}
	if len(f) > 1 {
		r.Timestamp = f[1]
	}
	if len(f) > 2 {
		r.Mimetype = f[2]
	}
	if len(f) > 3 {
		r.Statuscode = f[3]
	}
	return r, true
}

// normalizeCDXURL URL 规范化（§5.4）：scheme+host 小写、去 fragment、去尾斜杠。
// F4（终修轮）：最终 scheme ∉ {http,https} 返回 ""（调用方跳过）——敌意
// CDX 数据源的 javascript: 等行不进 rows/产物（无执行面，纯数据卫生）。
func normalizeCDXURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	u.Fragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return strings.ToLower(u.String())
	}
	s := u.String()
	return strings.TrimRight(s, "/")
}

// cdxHighExts 敏感扩展名（§5.4 清单）。
var cdxHighExts = []string{".bak", ".sql", ".zip", ".rar", ".7z", ".tar.gz", ".env", ".old", ".conf", ".ini", ".log"}

// cdxHighKeywords 敏感路径关键词（§5.4 清单）。
var cdxHighKeywords = []string{"admin", "login", "test", "backup", "upload", "ueditor", "phpinfo"}

// classifyCDXPath 敏感分流判定（命中即高危）。
func classifyCDXPath(path string) bool {
	lp := strings.ToLower(path)
	for _, ext := range cdxHighExts {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	for _, kw := range cdxHighKeywords {
		if strings.Contains(lp, kw) {
			return true
		}
	}
	return false
}

// pathsDictSet paths 模块字典集合（交叉标注用，包级缓存一次）。
var pathsDictSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range paths.PathsList {
		m[p] = true
	}
	return m
}()

// crossPathsDict 与 paths 字典交叉：在字典 → dup，否则 new。
func crossPathsDict(path string) string {
	if pathsDictSet[path] {
		return "dup"
	}
	return "new"
}

// cdxRetryWithBackoff 带退避的 CDX 单请求（3 次上限，§5.4 降级写法）。
func cdxRetryWithBackoff(rawURL string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < cdxRetries; attempt++ {
		if attempt > 0 {
			retrySleepCDX(time.Duration(attempt) * 500 * time.Millisecond)
		}
		body, err := cdxFetch(rawURL, cdxTimeout)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return "", lastErr
}

// fetchCDX 分页拉取 CDX 行（showNumPages → 逐页），行数封顶 maxLines、页数封顶。
// 展示页数接口不可用时回退单次请求（无 page 参数）。
func fetchCDX(domain string, maxLines int) (rows []cdxRow, truncated bool, err error) {
	baseQuery := fmt.Sprintf("%s?url=%s&fl=original,timestamp,mimetype,statuscode&collapse=urlkey",
		CDXBase, url.QueryEscape("*."+domain))
	seen := map[string]bool{}
	addLines := func(body string) {
		for _, ln := range strings.Split(body, "\n") {
			if strings.TrimSpace(ln) == "" {
				continue
			}
			r, ok := parseCDXLine(ln)
			if !ok {
				continue
			}
			key := normalizeCDXURL(r.Original)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			r.Original = key
			rows = append(rows, r)
			if len(rows) >= maxLines {
				truncated = true
				return
			}
		}
	}
	// 页数探测（失败回退单次全量）
	npBody, npErr := cdxRetryWithBackoff(baseQuery + "&showNumPages=true")
	if npErr != nil {
		return nil, false, npErr
	}
	var nPages int
	if _, err := fmt.Sscanf(strings.TrimSpace(npBody), "%d", &nPages); err != nil || nPages <= 0 {
		nPages = 1
	}
	if nPages > cdxMaxPages {
		nPages = cdxMaxPages
	}
	for p := 0; p < nPages; p++ {
		body, err := cdxRetryWithBackoff(fmt.Sprintf("%s&page=%d", baseQuery, p))
		if err != nil {
			if len(rows) > 0 {
				return rows, truncated, nil // 已取到的页照常产出
			}
			return nil, false, err
		}
		addLines(body)
		if truncated {
			return rows, truncated, nil
		}
	}
	return rows, truncated, nil
}

// archivesHigh 高危条目（交叉标注在册）。
type archivesHigh struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
	Cross  string `json:"cross"` // dup（paths 字典已有）/ new
}

// RunArchives 历史归档检查主流程（§5.4）。
func RunArchives(o Options) Result {
	res := NewResult(CheckArchives, o.Domain, "")
	rows, truncated, err := fetchCDX(o.Domain, cdxMaxLines)
	if err != nil {
		res.Error = fmt.Sprintf("CDX 接口不可用（%v），未编造结果", err)
		res.Conclusion = Conclusion{Level: LevelFail, Text: "历史归档源不可达"}
		res.Data["total"] = 0
		res.Data["high"] = []archivesHigh{}
		return res
	}

	// 敏感分流 + 交叉标注
	high := []archivesHigh{}
	for _, r := range rows {
		u, perr := url.Parse(r.Original)
		if perr != nil || u.Path == "" {
			continue
		}
		if classifyCDXPath(u.Path) {
			reason := "敏感路径"
			lp := strings.ToLower(u.Path)
			for _, ext := range cdxHighExts {
				if strings.HasSuffix(lp, ext) {
					reason = "敏感扩展名 " + ext
					break
				}
			}
			for _, kw := range cdxHighKeywords {
				if strings.Contains(lp, kw) {
					reason += " / 关键词 " + kw
					break
				}
			}
			high = append(high, archivesHigh{URL: r.Original, Reason: reason, Cross: crossPathsDict(u.Path)})
		}
	}
	if len(high) > 0 {
		res.Risks = append(res.Risks, Risk{Level: LevelWarn,
			Title:  fmt.Sprintf("历史快照发现 %d 条高危 URL（.bak/.sql/admin 等）", len(high)),
			Detail: "清单见 archives_high.txt；与 paths 字典交叉标注 dup/new，只出清单不自动探测"})
	}
	if truncated {
		res.Risks = append(res.Risks, Risk{Level: LevelInfo,
			Title: fmt.Sprintf("历史快照超过 %d 行上限，已截断", cdxMaxLines)})
	}

	// 产物：archives_high.txt（高危单列）
	if len(high) > 0 {
		var lines []string
		for _, h := range high {
			lines = append(lines, h.URL)
		}
		if _, err := netutil.SafeWrite(o.Out, "archives_high.txt", strings.Join(lines, "\n")); err != nil {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "archives_high.txt 写盘失败", Detail: err.Error()})
		}
	}

	sample := rows
	if len(sample) > 50 {
		sample = sample[:50]
	}
	res.Data["total"] = len(rows)
	res.Data["truncated"] = truncated
	res.Data["high"] = high
	res.Data["high_count"] = len(high)
	res.Data["sample"] = sample
	res.Data["summary"] = []string{
		fmt.Sprintf("历史快照 %d 条（去重后%s）", len(rows), map[bool]string{true: "，已截断", false: ""}[truncated]),
		fmt.Sprintf("高危 %d 条（paths 字典交叉标注）", len(high)),
	}
	res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf("历史快照 %d 条，高危 %d 条", len(rows), len(high))}
	if len(rows) == 0 {
		res.Conclusion = Conclusion{Level: LevelInfo, Text: "无历史快照记录（新域或未被收录）"}
	}
	return res
}
