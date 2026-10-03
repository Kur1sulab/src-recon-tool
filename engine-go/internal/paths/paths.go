// Package paths：敏感路径探测（软 404 基线 + 存活复验），移植 src/modules/paths.py。
// 判定流水线：基线 → 逐条 fetch → IsBaseline 过滤 → 200 才复验记存活 →
// 401/403 记被拒绝、30x 记跳转；请求完全失败的行不进任何产出（paths.py:42-43）。
package paths

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// PathsList 19 条逐字对照 paths.py:20-26。
var PathsList = []string{
	"/robots.txt", "/.git/config", "/.env", "/admin", "/admin/login",
	"/api/swagger", "/swagger-ui.html", "/v2/api-docs",
	"/wp-login.php", "/.svn/entries", "/.DS_Store",
	"/phpinfo.php", "/server-status", "/actuator", "/actuator/env",
	"/druid/index.html", "/backup.zip", "/www.zip", "/config.php.bak",
}

// Row 单行结果；JSON 键序对齐 paths.py:40-41（path/status/size/ctype/final_url/
// shrunk/verdict/verified/recheck）。verdict/verified/recheck 为动态键：未产生时
// omitempty 不输出（对齐 Python dict 只在有值时才有该键）；shrunk 恒为 null。
type Row struct {
	Path     string            `json:"path"`
	Status   int               `json:"status"`
	Size     int               `json:"size"`
	Ctype    string            `json:"ctype"`
	FinalURL string            `json:"final_url"`
	Shrunk   *string           `json:"shrunk"`
	Verdict  string            `json:"verdict,omitempty"`
	Verified *bool             `json:"verified,omitempty"`
	Recheck  []netutil.Attempt `json:"recheck,omitempty"`
}

// RunPaths 敏感路径探测主流程，对齐 paths.py:29-67。返回存活行。
func RunPaths(url, out string) ([]Row, error) {
	base := strings.TrimRight(url, "/")
	hop := netutil.HopPolicy(base) // fix2 P1：逐跳校验（策略由入口公网/私网推导）
	bl := netutil.Baseline(base, 0, hop)
	fmt.Printf("[*] 敏感路径探测: %s（%d 条字典）\n", url, len(PathsList))
	fmt.Printf("[*] 站点基线: %s（随机路径 → %d, %dB）\n", bl.Kind, bl.Status, bl.Size)
	switch bl.Kind {
	case "soft404", "uniform403", "redirect":
		fmt.Printf("[!] 存在 catch-all（%s），形态一致的响应不计入存活\n", bl.Kind)
	}
	var alive, notes []Row
	for _, p := range PathsList {
		r := netutil.Fetch(base+p, netutil.FetchOpt{Follow: true, HopCheck: hop})
		row := Row{
			Path: p, Status: r.Status, Size: r.Size, Ctype: r.Ctype,
			FinalURL: r.FinalURL,
		}
		if r.Status == 0 { // Python status is None → 完全跳过（paths.py:42-43）
			continue
		}
		if netutil.IsBaseline(r, bl) {
			row.Verdict = "与基线一致（catch-all，忽略）"
			notes = append(notes, row)
			continue
		}
		switch {
		case r.Status == 200:
			v := netutil.VerifyLive(base+p, 2, 0, "", hop)
			if v.Live {
				row.Verdict = "可访问"
			} else {
				row.Verdict = "200 但复验不一致（疑似瞬时）"
			}
			verified := v.Live
			row.Verified = &verified
			row.Recheck = v.Attempts
			if v.Live {
				alive = append(alive, row)
			}
		case r.Status == 401 || r.Status == 403:
			row.Verdict = "被拒绝（可能受保护/WAF）"
			notes = append(notes, row)
		case r.Status == 301 || r.Status == 302:
			row.Verdict = "跳转 → " + row.FinalURL
			notes = append(notes, row)
		}
	}
	doc := map[string]any{
		"base": url, "baseline": bl, "alive": alive, "notes": notes,
	}
	path, err := netutil.SafeWrite(out, "paths.json", jsonx.Pretty(doc))
	if err != nil {
		// fix3（audit medium#4）：上抛 → CLI exit 1 + fail 事件，对齐 Python safe_write 抛 ValueError
		fmt.Printf("[!] paths.json 写盘失败: %v\n", err)
		return nil, err
	}
	fmt.Printf("[+] 敏感路径探测完成（存活 %d 个，另有 %d 条被拒绝/跳转/基线过滤）-> %s\n",
		len(alive), len(notes), path)
	for _, row := range alive {
		fmt.Printf("      [可访问] %s  (%d, %dB, 复验通过)\n", row.Path, row.Status, row.Size)
	}
	return alive, nil
}
