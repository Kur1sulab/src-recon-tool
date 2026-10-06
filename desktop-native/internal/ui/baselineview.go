package ui

// baselineview.go —— 「暴露面仪表盘」产物读取器。渲染契约 =
// engine-go/internal/baseline/result.go 的冻结包络：
//
//	{check,target,url,generated_at,conclusion{level,text},risks[],data{},error}
//
// 两线对测试不对实现：引擎 schema 单测 + 本文件 fixture 单测双向钉住，任何
// 一侧改包络都会先红。语义纪律（不编造）：
//   - 产物文件缺失 → Loaded=false「未运行」空态；
//   - error 非空 → 失败态（检查级失败，聚合任务整体仍可 done）；
//   - 文件存在但 JSON 损坏 → 失败态并说明「产物解析失败」，不假装是引擎结论。
//
// 目录契约：outDirFor（evidence.go）三方同名目录——Python make_outdir /
// engine-go MakeOutdir / 本壳同规则，基线 8 个 json 落 <check>.json。

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"time"

	"recon-native/internal/store"
)

// baselineCheckMeta 一个检查的展示元数据（顺序 = 引擎 checksOrder，§5.1-5.8）。
// 中文名与 engine-go baseline.CheckLabels 按值同步（桌面不 import 引擎包，
// 双侧任一改动须同改——moduleLabel 映射与 results.go 测试钉住）。
type baselineCheckMeta struct {
	Key   string
	Label string
	Desc  string
}

// baselineChecks 8 项检查（顺序即仪表盘卡片排列顺序）。
var baselineChecks = []baselineCheckMeta{
	{"secheaders", "安全响应头", "HTTP 安全响应头 / HSTS / Cookie 属性 / WAF 指纹"},
	{"webfiles", "网站文件", "robots / sitemap / security.txt / og 元信息 / 外链域名归类"},
	{"mailsec", "邮件安全", "SPF / DMARC / DKIM 邮件防伪造记录分档"},
	{"archives", "历史归档", "Wayback 历史归档 URL 与敏感路径分流"},
	{"sslchain", "TLS 证书链", "证书面 / 证书链判定 / 协议支持矩阵"},
	{"dnsrec", "DNS 记录", "常见 DNS 记录类型体检（A/MX/TXT/NS 等）"},
	{"whois", "WHOIS 注册信息", "RDAP 注册信息与关键日期"},
	{"geoasn", "IP 归属 / ASN", "解析 IP 的地理位置与 ASN 归属"},
}

// BaselineRisk 单条风险发现（包络 risks[] 项）。
type BaselineRisk struct {
	Level  string
	Title  string
	Detail string
}

// BaselineResult 单检查产物（冻结包络的桌面侧形态）。
type BaselineResult struct {
	Check           string
	Target          string
	URL             string
	GeneratedAt     string
	ConclusionLevel string
	ConclusionText  string
	Risks           []BaselineRisk
	Summary         []string // data.summary（引擎自产的可读摘要行，各检查形态不一）
	Error           string   // 非空 = 失败态
	RawJSON         string   // 原始文件文本（卡片「原始 JSON」折叠展示用）
}

// BaselineCheckState 仪表盘一个检查槽位的当前态。
type BaselineCheckState struct {
	Key    string
	Label  string
	Desc   string
	Loaded bool // false = 产物缺失（未运行）
	Res    BaselineResult
}

// LoadBaselineProducts 读取目标当前的全部基线产物（8 槽位，顺序固定）。
// 任何单个文件读不了/解析不了都不影响其余槽位（各检查独立）。
func LoadBaselineProducts(repoRoot, target string) []BaselineCheckState {
	dir := outDirFor(repoRoot, target)
	out := make([]BaselineCheckState, 0, len(baselineChecks))
	for _, m := range baselineChecks {
		st := BaselineCheckState{Key: m.Key, Label: m.Label, Desc: m.Desc}
		if body, err := os.ReadFile(filepath.Join(dir, m.Key+".json")); err == nil {
			st.Loaded = true
			st.Res = parseBaselineResult(m.Key, body)
		}
		out = append(out, st)
	}
	return out
}

// parseBaselineResult 解析冻结包络。字段缺失/类型不符按零值收纳，坏 JSON
// 落 Error 失败态——绝不用猜测值补齐（空态与失败态是两种真实状态）。
// F6（终修轮）：risks 先解 []json.RawMessage 逐项转换、错型元素跳过——此前
// 混入一个裸字符串元素会毒化整个包络（json.Unmarshal 整体失败 → 结论/风险
// 全灭，违背「类型不符按零值收纳」自述契约）。Res.Check 以槽位文件名为准，
// 不信任内容 check 字段（文件名 secheaders.json 自称 webfiles 的错位展示）。
func parseBaselineResult(check string, body []byte) BaselineResult {
	res := BaselineResult{Check: check, RawJSON: string(body)}
	var env struct {
		Target      string `json:"target"`
		URL         string `json:"url"`
		GeneratedAt string `json:"generated_at"`
		Conclusion  struct {
			Level string `json:"level"`
			Text  string `json:"text"`
		} `json:"conclusion"`
		Risks []json.RawMessage `json:"risks"`
		Data  map[string]any    `json:"data"`
		Error string            `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		res.Error = "产物解析失败: " + err.Error()
		return res
	}
	for _, raw := range env.Risks {
		var r struct {
			Level  string `json:"level"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			continue // 错型元素跳过（不编造零值结论）
		}
		res.Risks = append(res.Risks, BaselineRisk{Level: r.Level, Title: r.Title, Detail: r.Detail})
	}
	res.Target = env.Target
	res.URL = env.URL
	res.GeneratedAt = env.GeneratedAt
	res.ConclusionLevel = env.Conclusion.Level
	res.ConclusionText = env.Conclusion.Text
	res.Error = env.Error
	// data.summary 引擎侧写的是 []string，JSON 读回来是 []any——只收字符串项
	if sums, ok := env.Data["summary"].([]any); ok {
		for _, s := range sums {
			if str, ok := s.(string); ok {
				res.Summary = append(res.Summary, str)
			}
		}
	}
	return res
}

// BaselineConclusionRows 选中基线任务在结果页过程表尾部的「每检查结论」行
// （结果页每个地方都有 UI：过程事件行之外，结论逐检查一行）。
func BaselineConclusionRows(states []BaselineCheckState) []ResultRow {
	rows := make([]ResultRow, 0, len(states))
	for _, st := range states {
		row := ResultRow{Time: baselineRowTime(st.Res.GeneratedAt), Module: st.Label}
		switch {
		case !st.Loaded:
			row.Event = "未运行"
		case st.Res.Error != "":
			row.Event = "结论"
			row.Detail = "[fail] " + st.Res.Error
		default:
			row.Event = "结论"
			row.Detail = "[" + st.Res.ConclusionLevel + "] " + st.Res.ConclusionText
		}
		rows = append(rows, row)
	}
	return rows
}

// baselineRowTime ISO 时间戳 → 表格短串（解析不了原样返回，空返回空）。
func baselineRowTime(iso string) string {
	if iso == "" {
		return ""
	}
	if ts, err := time.Parse(time.RFC3339, iso); err == nil {
		return ts.Format("15:04:05")
	}
	return iso
}

// taskStoreSignature 任务库快照签名（后台节拍用：变化即请求重绘）。
// 只依赖任务可见字段（id/状态/进度条数/时间戳），跨 goroutine 只读安全。
func taskStoreSignature(tasks []store.Task) uint64 {
	var b strings.Builder
	fmt.Fprintf(&b, "n=%d;", len(tasks))
	for _, t := range tasks {
		fmt.Fprintf(&b, "%s|%s|%d|%.3f|%.3f;", t.ID, t.Status, len(t.Progress), t.CreatedAt, t.FinishedAt)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(b.String()))
	return h.Sum64()
}

// baselineLevelColor 结论等级 → 色条/文字（包络 level 契约：
// ok→绿族 · warn→橙族 · fail→红族 · info→青族，全部取浅色主题既有常量）。
func baselineLevelColor(level string) (bg, fg colorNRGBA) {
	switch level {
	case "ok":
		return ColOkBg, ColOk
	case "warn":
		return ColWarnBg, ColWarn
	case "fail":
		return ColErrBg, ColErr
	case "info":
		return ColAccBg, ColAccHi
	}
	return ColIdleBg, ColTx2
}

// ── 仪表盘卡片相位（产品态 × 运行事件的合成，纯函数可测）──

// baselineEventStates 从基线任务的进度事件提取每检查的运行态：
// map[检查名]running|done|fail|skipped（同名事件取最后一条；任务级
// module=baseline 与 pipeline 不入表）。事件 module 名即检查名
//（引擎内层 start/done|fail|skipped 契约，§5.9）。
func baselineEventStates(evs []store.ProgressEvent) map[string]string {
	known := map[string]bool{}
	for _, m := range baselineChecks {
		known[m.Key] = true
	}
	out := map[string]string{}
	for _, ev := range evs {
		if !known[ev.Module] {
			continue
		}
		switch ev.Event {
		case "start":
			out[ev.Module] = "running"
		case "done":
			out[ev.Module] = "done"
		case "fail":
			out[ev.Module] = "fail"
		case "skipped":
			out[ev.Module] = "skipped"
		}
	}
	return out
}

// baselineCheckPhase 合成卡片显示相位（优先级：运行事件 > 产物 > 跳过事件
// > 排队/未运行）：
//   - running：事件流里该检查正在跑（压过旧产物——引擎逐检查重写同名文件，
//     运行中读到的是上一轮残留，不展示免误导）；
//   - conclusion：产物在且结论有效（无事件也成立：打开页面看历史产物）；
//   - failed：产物在但 error 非空（检查级失败态）；
//   - skipped：引擎发 skipped（总预算耗尽等）；
//   - queued：聚合任务运行中但该检查还没轮到；
//   - notrun：无任务无产物。
func baselineCheckPhase(st BaselineCheckState, ev string, taskRunning bool) string {
	switch ev {
	case "running":
		return "running"
	case "skipped":
		return "skipped"
	case "done", "fail":
		if st.Loaded {
			if st.Res.Error != "" {
				return "failed"
			}
			return "conclusion"
		}
		if taskRunning {
			return "queued"
		}
		return "notrun"
	}
	// 无事件（或事件被封顶丢弃）
	if st.Loaded {
		if st.Res.Error != "" {
			return "failed"
		}
		return "conclusion"
	}
	if taskRunning {
		return "queued"
	}
	return "notrun"
}

// baselinePhaseLabel 相位 → 卡片状态文字。
func baselinePhaseLabel(phase string) string {
	switch phase {
	case "notrun":
		return "未运行"
	case "queued":
		return "排队中"
	case "running":
		return "检查中…"
	case "skipped":
		return "已跳过"
	case "failed":
		return "执行失败"
	case "conclusion":
		return "有结论"
	}
	return phase
}

// baselinePhaseColor 相位 → LED/文字色（浅色主题既有常量，Idle 不作文字色）。
func baselinePhaseColor(phase string) colorNRGBA {
	switch phase {
	case "running":
		return ColAccHi
	case "conclusion":
		return ColOk
	case "failed", "skipped":
		return ColErr
	}
	return ColTx3
}
