package ui

// baselineview_test.go — 暴露面仪表盘产物读取器（与引擎线对测试不对实现：
// fixture 按 engine-go/internal/baseline/result.go 冻结包络手写）。
// 语义：缺文件=未运行空态（不编造）；error 非空=失败态；risks[] 出风险列表。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBaselineFixture(t *testing.T, repoRoot, target, check, body string) {
	t.Helper()
	dir := outDirFor(repoRoot, target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, check+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const fixtureSecHeaders = `{
  "check": "secheaders",
  "target": "example.com",
  "url": "https://example.com",
  "generated_at": "2026-10-06T10:00:00+08:00",
  "conclusion": {"level": "warn", "text": "缺 2 条安全头"},
  "risks": [
    {"level": "warn", "title": "缺 HSTS", "detail": "max-age 建议 ≥ 10886400"},
    {"level": "fail", "title": "缺 CSP"}
  ],
  "data": {"missing_count": 2, "summary": ["入口 https://example.com", "缺失: HSTS, CSP"]}
}`

const fixtureWebfilesFail = `{
  "check": "webfiles",
  "target": "example.com",
  "generated_at": "2026-10-06T10:00:01+08:00",
  "conclusion": {"level": "fail", "text": "执行超时，未取得完整结果"},
  "risks": [],
  "data": {},
  "error": "检查超时（60s 预算耗尽）"
}`

func TestLoadBaselineProducts(t *testing.T) {
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", fixtureSecHeaders)
	writeBaselineFixture(t, repoRoot, "example.com", "webfiles", fixtureWebfilesFail)

	states := LoadBaselineProducts(repoRoot, "example.com")
	if len(states) != 8 {
		t.Fatalf("应得 8 个检查槽位, 得 %d", len(states))
	}
	// 顺序 = 引擎 checksOrder（§5.1-5.8 编号序）
	wantOrder := []string{"secheaders", "webfiles", "mailsec", "archives", "sslchain", "dnsrec", "whois", "geoasn"}
	for i, w := range wantOrder {
		if states[i].Key != w {
			t.Fatalf("槽位 %d = %q, 期望 %q", i, states[i].Key, w)
		}
		if states[i].Label == "" {
			t.Fatalf("槽位 %s 应有中文名", w)
		}
	}
	// 完整包络解析
	sh := states[0]
	if !sh.Loaded {
		t.Fatal("secheaders 有产物应 Loaded")
	}
	if sh.Res.ConclusionLevel != "warn" || sh.Res.ConclusionText != "缺 2 条安全头" {
		t.Fatalf("结论不符: %+v", sh.Res)
	}
	if sh.Res.Target != "example.com" || sh.Res.URL != "https://example.com" {
		t.Fatalf("目标/入口不符: %+v", sh.Res)
	}
	if len(sh.Res.Risks) != 2 || sh.Res.Risks[1].Level != "fail" || sh.Res.Risks[1].Title != "缺 CSP" {
		t.Fatalf("风险列表不符: %+v", sh.Res.Risks)
	}
	if len(sh.Res.Summary) != 2 || !strings.Contains(sh.Res.Summary[1], "HSTS") {
		t.Fatalf("摘要不符: %+v", sh.Res.Summary)
	}
	if sh.Res.Error != "" {
		t.Fatalf("无错包络 Error 应为空: %q", sh.Res.Error)
	}
	if !strings.Contains(sh.Res.RawJSON, `"conclusion"`) {
		t.Fatal("RawJSON 应保留原始文件文本（折叠展示用）")
	}
	// 失败态：error 非空
	wf := states[1]
	if !wf.Loaded || wf.Res.Error != "检查超时（60s 预算耗尽）" {
		t.Fatalf("webfiles 应为失败态: Loaded=%v Err=%q", wf.Loaded, wf.Res.Error)
	}
	// 缺文件：未运行空态，不编造
	for _, st := range states[2:] {
		if st.Loaded {
			t.Fatalf("%s 缺文件应 Loaded=false", st.Key)
		}
		if st.Res.ConclusionText != "" || len(st.Res.Risks) != 0 {
			t.Fatalf("%s 空态不得编造内容: %+v", st.Key, st.Res)
		}
	}
}

func TestLoadBaselineProductsCorruptJSON(t *testing.T) {
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "mailsec", `{"check": "mailsec", "broken`)
	states := LoadBaselineProducts(repoRoot, "example.com")
	ms := states[2]
	if !ms.Loaded {
		t.Fatal("坏 JSON 文件存在应 Loaded（不是缺文件）")
	}
	if ms.Res.Error == "" || !strings.Contains(ms.Res.Error, "解析") {
		t.Fatalf("坏 JSON 应落失败态并说明原因: %+v", ms.Res)
	}
}

func TestLoadBaselineProductsNoFabrication(t *testing.T) {
	repoRoot := t.TempDir()
	states := LoadBaselineProducts(repoRoot, "nonexistent-target.example")
	for _, st := range states {
		if st.Loaded {
			t.Fatalf("%s 无产物不得 Loaded", st.Key)
		}
	}
}

func TestBaselineConclusionRows(t *testing.T) {
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", fixtureSecHeaders)
	writeBaselineFixture(t, repoRoot, "example.com", "webfiles", fixtureWebfilesFail)
	states := LoadBaselineProducts(repoRoot, "example.com")
	rows := BaselineConclusionRows(states)
	if len(rows) != 8 {
		t.Fatalf("每检查恰一行结论, 得 %d", len(rows))
	}
	// 正常结论行：模块中文名 + 事件「结论」+ 等级行情
	if rows[0].Module != "安全响应头" || rows[0].Event != "结论" {
		t.Fatalf("首行不符: %+v", rows[0])
	}
	if !strings.HasPrefix(rows[0].Detail, "[warn]") || !strings.Contains(rows[0].Detail, "缺 2 条安全头") {
		t.Fatalf("结论详情不符: %q", rows[0].Detail)
	}
	// 失败态行
	if !strings.HasPrefix(rows[1].Detail, "[fail]") || !strings.Contains(rows[1].Detail, "检查超时") {
		t.Fatalf("失败行不符: %q", rows[1].Detail)
	}
	// 未运行行
	if rows[2].Event != "未运行" || rows[2].Detail != "" {
		t.Fatalf("未运行行不符: %+v", rows[2])
	}
}

func TestModuleLabelsBaseline(t *testing.T) {
	// 任务级：Modules 表新增 baseline
	found := false
	for _, m := range Modules {
		if m.Key == "baseline" {
			found = true
			if m.Label != "基线检查" {
				t.Fatalf("baseline 中文名 = %q", m.Label)
			}
		}
	}
	if !found {
		t.Fatal("Modules 表应有 baseline 行（结果页 tab 自动多一枚基线胶囊）")
	}
	if moduleLabel("baseline") != "基线检查" {
		t.Fatalf("moduleLabel(baseline) = %q", moduleLabel("baseline"))
	}
	// 8 个子检查事件 module 名映射（缺失只影响显示文案不崩——钉住中文映射存在）
	want := map[string]string{
		"secheaders": "安全响应头", "webfiles": "网站文件", "mailsec": "邮件安全",
		"archives": "历史归档", "sslchain": "TLS 证书链", "dnsrec": "DNS 记录",
		"whois": "WHOIS 注册信息", "geoasn": "IP 归属 / ASN",
	}
	for k, w := range want {
		if moduleLabel(k) != w {
			t.Fatalf("moduleLabel(%s) = %q, 期望 %q", k, moduleLabel(k), w)
		}
	}
	// tab 自动派生：含「全部」+ 8 模块（jsintel/portscan 退役后随之收缩）
	tabs := tabKeys()
	if len(tabs) != len(Modules)+1 {
		t.Fatalf("tab 数 = %d, 期望 %d", len(tabs), len(Modules)+1)
	}
}
