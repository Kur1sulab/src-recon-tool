// result.go — 域名暴露面基线检查的统一 JSON 包络（schema 冻结，桌面线
// baselineview 按「{check,target,url,generated_at,conclusion,risks,data,error}」
// 渲染：缺文件=「未运行」空态、error 非空=失败态、risks[] 出风险列表、
// conclusion.level 出结论色条。两线对测试不对实现：本文件即契约，改动需
// 双线同步（引擎 schema + 桌面 fixture 单测）。
//
// level 取值契约（桌面色条映射 ok→ColOkBg · warn→ColWarnBg · fail→ColErrBg 族）：
//
//	ok=通过 / warn=注意 / fail=风险 / info=信息（如 WAF 指纹命中、security.txt 存在）。
package baseline

import "time"

// 结论/风险四级（冻结常量，桌面渲染契约）。
const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelFail = "fail"
	LevelInfo = "info"
)

// Conclusion 检查结论（跑完之后的体检判断，与执行是否出错无关——
// 执行错误走 Error 字段）。
type Conclusion struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Risk 单条风险发现。
type Risk struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// Result 统一包络。Data 是模块专属载荷（各检查自定义键），risks 空时序列化
// 为 []（非 null），error 为空时 omitempty 不输出。
type Result struct {
	Check       string         `json:"check"`
	Target      string         `json:"target"`
	URL         string         `json:"url,omitempty"`
	GeneratedAt string         `json:"generated_at"`
	Conclusion  Conclusion     `json:"conclusion"`
	Risks       []Risk         `json:"risks"`
	Data        map[string]any `json:"data"`
	Error       string         `json:"error,omitempty"`
}

// nowFn 时钟（测试可注入）。
var nowFn = time.Now

// NewResult 构造空包络：基础字段就位，Risks/Data 非空集合，generated_at 本地时区
// ISO 秒级（与 report 包同形态）。
func NewResult(check, target, url string) Result {
	return Result{
		Check:       check,
		Target:      target,
		URL:         url,
		GeneratedAt: nowFn().Format("2006-01-02T15:04:05Z07:00"),
		Risks:       []Risk{},
		Data:        map[string]any{},
	}
}
