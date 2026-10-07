// Package apiunauth：API 文档暴露与未授权访问探测，移植 src/modules/api_unauth.py。
// 判定流水线：200 → 技术特征（多特征端点需 ≥2）→ 基线比对刷假阳性 →
// 存活复验记 live；命中仅代表疑似，报告须人工复核（反幻觉纪律）。
package apiunauth

import (
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// Endpoint 对齐 api_unauth.py:22-50 的 (路径, 名称, 特征[小写], 风险)。
type Endpoint struct {
	Path   string
	Name   string
	Expect []string
	Risk   string
}

// Endpoints 27 条逐字对照 api_unauth.py:22-50。
var Endpoints = []Endpoint{
	{"/swagger-ui.html", "Swagger UI", []string{"swagger-ui"}, "中"},
	{"/swagger-ui/index.html", "Swagger UI", []string{"swagger-ui"}, "中"},
	{"/swagger-resources", "Swagger 资源列表", []string{"swagger"}, "中"},
	{"/v2/api-docs", "Swagger API-Docs (v2)", []string{`"swagger"`, `"paths"`}, "中"},
	{"/v3/api-docs", "OpenAPI 3 文档", []string{`"openapi"`, `"paths"`}, "中"},
	{"/openapi.json", "OpenAPI 描述文件", []string{`"openapi"`}, "中"},
	{"/api-docs", "API 文档", []string{`"swagger"`, `"openapi"`}, "中"},
	{"/redoc", "ReDoc 文档", []string{"redoc"}, "低"},
	{"/actuator", "Spring Boot Actuator", []string{`"_links"`, `"href"`}, "中"},
	{"/actuator/env", "Actuator env（含配置/口令）", []string{`"propertysources"`}, "高"},
	{"/actuator/health", "Actuator health", []string{`"status"`}, "低"},
	{"/actuator/mappings", "Actuator mappings（全路由）", []string{`"mappings"`}, "中"},
	{"/actuator/beans", "Actuator beans", []string{`"beans"`}, "中"},
	{"/actuator/heapdump", "Heapdump（可提取凭据）", []string{"java profile"}, "高"},
	{"/druid/index.html", "Druid 监控台", []string{"druid"}, "中"},
	{"/druid/websession.json", "Druid 会话（含登录态）", []string{`"result"`}, "高"},
	{"/druid/sql.json", "Druid SQL 监控", []string{`"result"`}, "中"},
	{"/graphql", "GraphQL 端点", []string{`"errors"`, `"data"`}, "中"},
	{"/graphiql", "GraphiQL 交互台", []string{"graphiql"}, "中"},
	{"/eureka/apps", "Eureka 注册中心", []string{"<applications"}, "中"},
	{"/nacos/", "Nacos 控制台", []string{"nacos"}, "中"},
	{"/nacos/v1/auth/users", "Nacos 用户接口（CVE-2021-29441）", []string{"username", `"pageitems"`}, "高"},
	{"/v1/agent/members", "Consul 成员列表", []string{`"member"`}, "中"},
	{"/h2-console", "H2 数据库控制台", []string{"h2-console"}, "中"},
	{"/debug/pprof/", "Go pprof 调试面", []string{"pprof"}, "中"},
	{"/metrics", "Prometheus 指标", []string{"# help"}, "低"},
	{"/api/v1/users", "常见 API：用户列表", []string{`"username"`, `"email"`}, "中"},
}

// Verdict 判定结果（JSON 键对齐 classify 返回 dict）。
type Verdict struct {
	Hit      bool   `json:"hit"`
	Marker   string `json:"marker,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// Classify 只看内容特征，对齐 api_unauth.py:53-64：
// status!=200 miss；expect 非空时 need = len(expect)>=2 ? 2 : 1；
// evidence = "body 含 " + 前 3 个命中特征逗号连接。
func Classify(path string, status int, body, ctype string, size int, expect []string) Verdict {
	if status != 200 {
		return Verdict{Hit: false}
	}
	low := strings.ToLower(body)
	if len(expect) > 0 {
		var matched []string
		for _, k := range expect {
			if strings.Contains(low, k) {
				matched = append(matched, k)
			}
		}
		need := 1
		if len(expect) >= 2 {
			need = 2
		}
		if len(matched) < need {
			return Verdict{Hit: false}
		}
		top := matched
		if len(top) > 3 {
			top = top[:3]
		}
		return Verdict{Hit: true, Marker: matched[0], Evidence: "body 含 " + strings.Join(top, ", ")}
	}
	return Verdict{Hit: false}
}

// statusOrNil/errOrNil 对齐 Python r.get("status")/r.get("error") 的 null 语义
// （fix2 audit low#3①）：请求成功 → status int / error null；失败 → status null /
// error 字符串。此前 Go 恒出 int/""，落盘 JSON 键型与 Python 漂移。
// reproAttemptsJSON 把 attempts 渲染成 JSON 文本（fix3 audit low#7：
// 此前 %v 渲染 Go 结构体形态；JSON 形态无歧义且带 Attempt 的 null 语义）。
func reproAttemptsJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// pyNone 对齐 Python print 对 None 的字面渲染（展示层，fix3 audit low#7）。
func pyNone(v any) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%v", v)
}

func statusOrNil(r netutil.Result) any {
	if r.OK {
		return r.Status
	}
	return nil
}

func sizeOrNil(r netutil.Result) any {
	if r.OK {
		return r.Size
	}
	return nil
}

func digestOrNil(r netutil.Result) any {
	if r.OK {
		return r.Digest
	}
	return nil
}

func errOrNil(r netutil.Result) any {
	if r.Err != "" {
		return r.Err
	}
	return nil
}

// Probe 探测主流程，对齐 api_unauth.py:67-98。rows/hits 用 map 保持动态键
// （Python **verdict 展开语义）；hits 排序 = live 优先、风险 高0中1低2（稳定排序）。
func Probe(baseURL string, timeout time.Duration, verify bool) ([]map[string]any, []map[string]any) {
	return probeCtx(context.Background(), baseURL, timeout, verify)
}

// probeCtx 是 Probe 的取消变体（第一步「取消能力注入」①）：基线探针与逐端点
// 请求全过取消咽喉，端点循环逐条设检查点——取消立即收敛已收集结果
// （外层 RunAPIContext 据此上抛 ctx.Err()）。旧签名委托本函数，存量测试零改动。
func probeCtx(ctx context.Context, baseURL string, timeout time.Duration, verify bool) ([]map[string]any, []map[string]any) {
	if ctx == nil {
		ctx = context.Background()
	}
	base := strings.TrimRight(baseURL, "/")
	hop := netutil.HopPolicy(base) // fix2 P1 + fix3：基线/主探测/复验共用同一逐跳策略
	bl := netutil.BaselineCtx(ctx, base, timeout, hop)
	blStatus := any(bl.Status)
	if bl.Kind == "unknown" {
		blStatus = nil // fix3（audit low#7）：对齐 Python bl.get("status") 的 None 渲染
	}
	fmt.Printf("[*] 站点基线: %s（随机路径 → %s, %dB, %s）\n", bl.Kind, pyNone(blStatus), bl.Size, dashEmpty(bl.Ctype))
	switch bl.Kind {
	case "soft404", "uniform403", "redirect":
		fmt.Printf("[!] 该站存在 catch-all（%s），已启用形态比对过滤——假阳性会被剔除\n", bl.Kind)
	}
	var rows, hits []map[string]any
	for _, ep := range Endpoints {
		if err := ctx.Err(); err != nil { // 逐端点检查点（第一步①）
			return rows, hits
		}
		u := base + ep.Path
		r := netutil.Fetch(u, netutil.FetchOpt{Timeout: timeout, Follow: true, HopCheck: hop, Ctx: ctx})
		verdict := Classify(ep.Path, r.Status, r.Body, r.Ctype, r.Size, lowerAll(ep.Expect))
		row := map[string]any{
			"path": ep.Path, "name": ep.Name, "risk": ep.Risk,
			"status": statusOrNil(r), "size": r.Size, "digest": r.Digest,
			"ctype": r.Ctype, "final_url": r.FinalURL, "error": errOrNil(r),
			"hit": verdict.Hit,
		}
		if verdict.Hit {
			row["marker"] = verdict.Marker
			row["evidence"] = verdict.Evidence
			if netutil.IsBaseline(r, bl) {
				row["hit"] = false
				row["soft404"] = true
				row["evidence"] = (verdict.Evidence) + " / 与站点基线形态一致（catch-all）"
			} else {
				if verify {
					v := netutil.VerifyLiveCtx(ctx, u, 2, timeout, verdict.Marker, hop)
					row["live"] = v.Live
					row["recheck"] = v
				}
				row["redirected"] = r.FinalURL != "" && r.FinalURL != u
				hits = append(hits, row)
				flag := "复验未通过✗"
				if b, _ := row["live"].(bool); b {
					flag = "存活✓"
				}
				fmt.Printf("[!] %s危  命中 %-34s %s  (%s) → %s\n", ep.Risk, ep.Name, ep.Path, verdict.Evidence, flag)
			}
		}
		rows = append(rows, row)
	}
	order := map[string]int{"高": 0, "中": 1, "低": 2}
	rank := func(s string) int { // 对齐 Python order.get(risk, 3)：表外值排尾
		if v, ok := order[s]; ok {
			return v
		}
		return 3
	}
	sort.SliceStable(hits, func(i, j int) bool {
		li, _ := hits[i]["live"].(bool)
		lj, _ := hits[j]["live"].(bool)
		if li != lj {
			return li // live 优先（Python not live: False<True）
		}
		ri, _ := hits[i]["risk"].(string)
		rj, _ := hits[j]["risk"].(string)
		return rank(ri) < rank(rj)
	})
	return rows, hits
}

// SaveEvidence 对存活命落盘存证，对齐 api_unauth.py:101-158：
// evidence/<host>/<slug>/ 三件套（meta.json / response.snippet.txt / repro.md）。
// host/slug 均白名单清洗+去首尾点，杜绝畸形 URL 的目录穿越。
func SaveEvidence(row map[string]any, out string) (map[string]any, error) {
	return saveEvidenceCtx(context.Background(), row, out)
}

// saveEvidenceCtx 是 SaveEvidence 的取消变体（第一步①）：取证请求过取消咽喉。
// 旧签名委托本函数，存量测试零改动。
func saveEvidenceCtx(ctx context.Context, row map[string]any, out string) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rawURL := strOr(row["url"], strOr(row["base"], "")+strOr(row["path"], ""))
	u, err := neturl.Parse(rawURL)
	host := "unknown"
	if err == nil {
		host = safeName(strings.ReplaceAll(u.Host, ":", "_"))
	}
	// 对齐 Python 顺序：re.sub 后先 strip("_") 再过 _safe 白名单
	slug := safeName(strings.Trim(slugRe.ReplaceAllString(strOr(row["path"], ""), "_"), "_"))
	d, err := netutil.SafeSubdir(out, "evidence", host, slug)
	if err != nil {
		return nil, err
	}
	ts := time.Now().Format("2006-01-02T15:04:05Z07:00") // astimezone().isoformat(seconds) 等价

	// fix2 P1：取证请求同样逐跳校验（该 URL 可能已被 302 带离入口）
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: 15 * time.Second, Follow: true,
		HopCheck: netutil.HopPolicy(rawURL), Ctx: ctx})
	recheckAttempts := attemptsOf(row["recheck"])
	meta := map[string]any{
		// fix3（audit medium#3）：对齐 api_unauth.py:124 r.get() 的 null 语义——
		// 请求失败时 status/size/digest 为 null 而非 0/""
		"url": rawURL, "collected_at": ts, "status": statusOrNil(r), "size": sizeOrNil(r),
		"digest": digestOrNil(r), "ctype": r.Ctype, "server": r.Headers["server"],
		"name": row["name"], "risk": row["risk"], "evidence": row["evidence"],
		"live": row["live"], "recheck": recheckAttempts,
	}
	if _, err := netutil.SafeWrite(d, "meta.json", jsonx.Pretty(meta)); err != nil {
		return nil, err
	}
	snippet := fmt.Sprintf("# %s\n# %s  status=%d size=%d ctype=%s digest=%s\n"+
		"# ⚠️ 可能含敏感信息，勿外传；报告脱敏后引用\n%s\n%s",
		rawURL, ts, r.Status, r.Size, r.Ctype, r.Digest, strings.Repeat("-", 60), trunc4000(r.Body))
	if _, err := netutil.SafeWrite(d, "response.snippet.txt", snippet); err != nil {
		return nil, err
	}
	marker := strOr(row["marker"], strOr(row["evidence"], ""))
	repro := fmt.Sprintf(`# 证据：%s（%s危）

- URL：`+"`%s`"+`
- 采集时间：%s
- 状态码 %d · 大小 %d B · Content-Type `+"`%s`"+`
- 判定依据：%s
- 存活复验：连续两次形态一致（%s）

## 复现命令

`+"```bash"+`
# 未携带任何凭证，直接请求（未授权即可访问）
curl -sk -i '%s' | head -c 2000
`+"```"+`

## 预期现象

命中特征「%s」在响应中出现，且无需登录态。

## 使用提醒

1. 该响应可能含配置、口令或会话信息 —— **不要外传、不要入库、报告内脱敏**；
2. 提交前用上面的命令复跑一次（证明仍然存活），并把响应片段作为证据附件；
3. 报告只写实测到的内容，不做推断性描述。
`,
		strOr(row["name"], ""), strOr(row["risk"], ""), rawURL, ts, r.Status, r.Size, r.Ctype,
		strOr(row["evidence"], ""), reproAttemptsJSON(recheckAttempts), rawURL, marker)
	if _, err := netutil.SafeWrite(d, "repro.md", repro); err != nil {
		return nil, err
	}
	return map[string]any{"dir": d, "meta": meta}, nil
}

// RunAPI 探测+取证+落盘，对齐 api_unauth.py:161-190。返回 hits。
func RunAPI(url, out string, evidence bool) ([]map[string]any, error) {
	return RunAPIContext(context.Background(), url, out, evidence)
}

// RunAPIContext 是 RunAPI 的取消变体（第一步「取消能力注入」①）：探测
// （probeCtx）与取证（saveEvidenceCtx）走取消变体，逐存证设检查点——
// 取消立即收敛返回 ctx.Err()、不落盘。旧签名委托本函数，cli.go 调用点零改动。
func RunAPIContext(ctx context.Context, url, out string, evidence bool) ([]map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fmt.Printf("[*] API 文档/未授权探测: %s（%d 个候选端点）\n", url, len(Endpoints))
	rows, hits := probeCtx(ctx, url, 0, true)
	if err := ctx.Err(); err != nil { // 探测后检查点：取消不落盘（第一步①）
		return nil, err
	}
	var live []map[string]any
	for _, h := range hits {
		if b, _ := h["live"].(bool); b {
			live = append(live, h)
		}
	}
	var soft int
	for _, r := range rows {
		if b, _ := r["soft404"].(bool); b {
			soft++
		}
	}
	for _, h := range live {
		h["url"] = strings.TrimRight(url, "/") + strOr(h["path"], "")
	}
	if evidence && len(live) > 0 {
		fmt.Printf("[*] 取证模式：为 %d 个存活命中落盘存证\n", len(live))
		for _, h := range live {
			if err := ctx.Err(); err != nil { // 逐存证检查点（第一步①）
				return nil, err
			}
			ev, err := saveEvidenceCtx(ctx, h, out)
			if err != nil {
				fmt.Printf("      [!] %s 存证失败: %v\n", h["path"], err)
				continue
			}
			h["evidence_dir"] = ev["dir"]
			rel, rerr := filepath.Rel(out, fmt.Sprintf("%v", ev["dir"]))
			if rerr != nil {
				rel = fmt.Sprintf("%v", ev["dir"])
			}
			fmt.Printf("      存证 %s -> %s\n", h["path"], rel)
		}
	}
	doc := map[string]any{
		"base": url, "probed": len(rows), "hits": hits, "live_hits": len(live),
		"soft404_filtered": soft, "all": rows,
	}
	path, err := netutil.SafeWrite(out, "api_unauth.json", jsonx.Pretty(doc))
	if err != nil {
		// fix3（audit medium#4）：上抛 → CLI exit 1 + fail 事件，对齐 Python safe_write 抛 ValueError
		fmt.Printf("[!] api_unauth.json 写盘失败: %v\n", err)
		return nil, err
	}
	if len(hits) > 0 {
		fmt.Printf("[+] 探测完成：%d 个疑似命中，其中**存活复验通过 %d 个**（catch-all 过滤掉 %d 条）\n",
			len(hits), len(live), soft)
		for i, r := range hits {
			if i >= 15 {
				break
			}
			state := "未复验通过"
			if b, _ := r["live"].(bool); b {
				state = "存活"
			}
			fmt.Printf("      [%s][%s] %s  %s\n", state, r["risk"], r["name"], r["path"])
		}
	} else {
		fmt.Printf("[*] 探测完成：未发现暴露的 API 文档/运维端点（catch-all 过滤掉 %d 条疑似）\n", soft)
	}
	fmt.Printf("    -> %s\n", path)
	return hits, nil
}

// ── 小工具 ──

var slugRe = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// safeName 对齐 api_unauth.py:_safe：白名单清洗 + 截 64 + 去首尾点，空回 unknown。
func safeName(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	r := []rune(b.String())
	if len(r) > 64 {
		r = r[:64]
	}
	s = strings.Trim(string(r), ".")
	if s == "" {
		return "unknown"
	}
	return s
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func dashEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// attemptsOf 从 recheck（LiveResult 或 map）取 attempts；缺 → nil（JSON null，对齐 Python）。
func attemptsOf(v any) any {
	switch rv := v.(type) {
	case netutil.LiveResult:
		return rv.Attempts
	case *netutil.LiveResult:
		if rv != nil {
			return rv.Attempts
		}
	case map[string]any:
		if a, ok := rv["attempts"]; ok {
			return a
		}
	}
	return nil
}

func trunc4000(s string) string {
	r := []rune(s)
	if len(r) > 4000 {
		r = r[:4000]
	}
	return string(r)
}
