// Package paths：敏感路径探测（软 404 基线 + 存活复验），移植 src/modules/paths.py。
// 判定流水线：基线 → 逐条 fetch → IsBaseline 过滤 → 200 才复验记存活 →
// 401/403 记被拒绝、30x 记跳转；请求完全失败的行不进任何产出（paths.py:42-43）。
package paths

import (
	"context"
	"fmt"
	"strings"

	"github.com/Kur1sulab/src-recon-tool/engine-go/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
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

// mergeExtra --extra 补充字典归并（report §5.2）：extra 条目（一行一路径）
// 去重、剔空、剔除与内置字典重复项、保序——返回值直接追加到 PathsList。
func mergeExtra(extra []string) []string {
	inDict := map[string]bool{}
	for _, p := range PathsList {
		inDict[p] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range extra {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || inDict[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// RunPaths 敏感路径探测主流程，对齐 paths.py:29-67。返回存活行。
// extra 为补充字典条目（--extra 文件读入，一行一路径，如 baseline webfiles
// 产出的 paths_extra.txt），归并去重后与内置字典一并探测。
func RunPaths(url, out string, extra ...string) ([]Row, error) {
	return RunPathsContext(context.Background(), url, out, extra...)
}

// RunPathsContext 是 RunPaths 的取消变体（第一步「取消能力注入」①）：
// 基线探针/逐条探测/存活复验全部过取消咽喉，字典循环逐条设检查点——
// 取消立即收敛返回 ctx.Err()、不落盘。旧签名委托本函数，cli.go 调用点零改动。
func RunPathsContext(ctx context.Context, url, out string, extra ...string) ([]Row, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := strings.TrimRight(url, "/")
	hop := netutil.HopPolicy(base) // fix2 P1：逐跳校验（策略由入口公网/私网推导）
	dict := append(append([]string{}, PathsList...), mergeExtra(extra)...)
	bl := netutil.BaselineCtx(ctx, base, 0, hop)
	fmt.Printf("[*] 敏感路径探测: %s（%d 条字典）\n", url, len(dict))
	fmt.Printf("[*] 站点基线: %s（随机路径 → %d, %dB）\n", bl.Kind, bl.Status, bl.Size)
	switch bl.Kind {
	case "soft404", "uniform403", "redirect":
		fmt.Printf("[!] 存在 catch-all（%s），形态一致的响应不计入存活\n", bl.Kind)
	}
	var alive, notes []Row
	for _, p := range dict {
		if err := ctx.Err(); err != nil { // 逐条检查点（第一步①）
			return nil, err
		}
		r := netutil.Fetch(base+p, netutil.FetchOpt{Follow: true, HopCheck: hop, Ctx: ctx})
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
			v := netutil.VerifyLiveCtx(ctx, base+p, 2, 0, "", hop)
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
