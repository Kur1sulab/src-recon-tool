package ui

// adv_baselineview_test.go — 对抗轮（2026-10-06）：伪造基线 JSON 打桌面渲染线。
// 假设：产物目录可被任意写入（<check>.json 是引擎产物，也可能是用户/第三方
// 手工放置的文件）。验收口径：坏 JSON → 明示「产物解析失败」失败态（不假装
// 是引擎结论）；敌意字段 → 零值收纳不崩溃；渲染层纯文本直出（无解释层可注入）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"recon-native/internal/store"
)

// ── 1. 坏 JSON：必须落「产物解析失败」失败态，绝不用猜测值补齐 ──

func TestAdvUIBrokenJSONStates(t *testing.T) {
	cases := map[string]string{
		"空文件":     "",
		"纯垃圾":      "not json at all",
		"截断JSON":   `{"check":"secheaders","target":"example.com","conclu`,
		"BOM前缀":    "\xef\xbb\xbf" + `{"check":"secheaders"}`,
		"顶层数组":     `[1,2,3]`,
		"二进制垃圾":    "\x00\x01\x02\xff\xfe{}",
		"双JSON粘包":  `{"check":"a"}{"check":"b"}`,
		"裸NaN":     `{"check":"a","data":{"x":NaN}}`,
		"注释尾随":     `{"check":"a"} /* trailing */`,
		// F6（终修轮）后 check 字段不再解析绑定，键冲突样例换到仍绑定的
		// target 字段——坏 JSON 检测契约保持在仍被解析的字段上。
		"唯一键类型冲突": `{"target":"a","target":123}`,
	}
	for name, body := range cases {
		repoRoot := t.TempDir()
		writeBaselineFixture(t, repoRoot, "example.com", "secheaders", body)
		states := LoadBaselineProducts(repoRoot, "example.com")
		var st *BaselineCheckState
		for i := range states {
			if states[i].Key == "secheaders" {
				st = &states[i]
			}
		}
		if st == nil || !st.Loaded {
			t.Fatalf("[%s] 文件在场应 Loaded=true", name)
		}
		if !strings.Contains(st.Res.Error, "产物解析失败") {
			t.Errorf("[%s] 坏 JSON 应明示解析失败, Error=%q", name, st.Res.Error)
		}
		if st.Res.ConclusionText != "" || st.Res.ConclusionLevel != "" {
			t.Errorf("[%s] 坏 JSON 不得编造结论: level=%q text=%q", name, st.Res.ConclusionLevel, st.Res.ConclusionText)
		}
		if len(st.Res.Risks) != 0 {
			t.Errorf("[%s] 坏 JSON 不得编造风险: %+v", name, st.Res.Risks)
		}
		// 失败态在结论行可见
		rows := BaselineConclusionRows(states)
		found := false
		for _, r := range rows {
			if strings.HasPrefix(r.Detail, "[fail] ") {
				found = true
			}
		}
		if !found {
			t.Errorf("[%s] 结论行未呈现失败态", name)
		}
		// 相位：failed（失败态不可冒充 conclusion）
		if ph := baselineCheckPhase(*st, "", false); ph != "failed" {
			t.Errorf("[%s] 相位应 failed, 得 %s", name, ph)
		}
	}
}

// 其余 7 槽位不受单文件损坏影响（各检查独立）。
func TestAdvUIBrokenJSONIsolation(t *testing.T) {
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", "{broken")
	writeBaselineFixture(t, repoRoot, "example.com", "webfiles", fixtureSecHeaders)
	states := LoadBaselineProducts(repoRoot, "example.com")
	if len(states) != 8 {
		t.Fatalf("应 8 槽位, 得 %d", len(states))
	}
	for _, st := range states {
		switch st.Key {
		case "secheaders":
			if !strings.Contains(st.Res.Error, "产物解析失败") {
				t.Error("secheaders 应失败态")
			}
		case "webfiles":
			if st.Res.Error != "" || st.Res.ConclusionText == "" {
				t.Errorf("webfiles 应正常收纳结论: %+v", st.Res)
			}
		default:
			if st.Loaded {
				t.Errorf("%s 无文件却 Loaded", st.Key)
			}
		}
	}
}

// ── 2. 敌意但合法 JSON：错型/巨串/未知 level/check 错位 ──

func TestAdvUIForgedFields(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	forged := `{
		"check": "webfiles",
		"target": "` + strings.Repeat("t", 4096) + `",
		"url": "javascript:alert(1)",
		"generated_at": "not-a-timestamp",
		"conclusion": {"level": "pwned", "text": "` + big + `"},
		"risks": [
			{"level": "` + big + `", "title": "kernel !#$%&'()*+,-./:;<=>?@[]^_{|}~", "detail": "` + big + `"},
			{"level": null, "title": null, "detail": null},
			{}
		],
		"data": {"summary": ["ok-line", 42, true, null, {"x":1}, "` + strings.Repeat("S", 1<<20) + `"]},
		"error": ""
	}`
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", forged)
	states := LoadBaselineProducts(repoRoot, "example.com")
	var st *BaselineCheckState
	for i := range states {
		if states[i].Key == "secheaders" {
			st = &states[i]
		}
	}
	if st.Res.Error != "" {
		t.Fatalf("合法 JSON 不应判解析失败: %s", st.Res.Error)
	}
	// check 槽位为准（F6 已修·终修轮）：内容 check 字段不再覆盖 Res.Check——
	// 文件名 secheaders.json 自称 webfiles 时以槽位文件名为准，防错位展示。
	if st.Res.Check != "secheaders" || st.Key != "secheaders" {
		t.Errorf("check 槽位为准: Key=%s Res.Check=%s", st.Key, st.Res.Check)
	}
	// 未知 level → 默认配色（不崩溃、不误染 ok/fail 色）
	if bg, fg := baselineLevelColor("pwned"); bg != ColIdleBg || fg != ColTx2 {
		t.Error("未知 level 应回退默认色")
	}
	if _, fg := baselineLevelColor(big); fg != ColTx2 {
		t.Error("超长 level 应回退默认色")
	}
	// 垃圾时间戳原样返回（不猜格式）
	if got := baselineRowTime("not-a-timestamp"); got != "not-a-timestamp" {
		t.Errorf("垃圾时间戳应原样透传, 得 %q", got)
	}
	if got := baselineRowTime(big); len(got) != len(big) {
		t.Errorf("超长时间戳应原样透传")
	}
	// risks 错型项被丢弃、合法项收纳（零值字段不编造）
	if len(st.Res.Risks) == 0 {
		t.Fatal("risks 合法项应收纳")
	}
	// summary 只收字符串项（1MB 项如实收纳，不静默截断）
	sawBig := false
	for _, s := range st.Res.Summary {
		if len(s) > 1<<19 {
			sawBig = true
		}
	}
	if !sawBig {
		t.Error("summary 1MB 字符串项应收纳（如实展示）")
	}
	// 结论行透传敌意串（结构性无解释层：Gio 纯文本直出，无 HTML 转义面）
	rows := BaselineConclusionRows(states)
	var secRow *ResultRow
	for i := range rows {
		if rows[i].Module == "安全响应头" {
			secRow = &rows[i]
		}
	}
	if secRow == nil {
		t.Fatal("结论行缺安全响应头")
	}
	if !strings.Contains(secRow.Detail, "A") || len(secRow.Detail) < 1<<19 {
		t.Errorf("结论行应透传敌意串原文（长度 %d）", len(secRow.Detail))
	}
}

// 脆弱点（对抗轮发现 F6）：risks 数组里混入一个裸字符串元素——字段级错型，
// 却令整个包络 json.Unmarshal 失败 → 全检查落「产物解析失败」。方向是
// F6 已修（终修轮）：risks 逐项解包，错型元素跳过不再毒化整个包络——
// 合法字段（结论/风险）保留，语法级坏 JSON 仍落「产物解析失败」失败态。
func TestAdvUIRisksWrongTypedElementSkipped(t *testing.T) {
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders",
		`{"check":"secheaders","conclusion":{"level":"ok","text":"fine"},"risks":["not-an-object"]}`)
	states := LoadBaselineProducts(repoRoot, "example.com")
	st := states[0]
	if st.Res.Error != "" {
		t.Errorf("错型风险元素应逐项跳过而非整包络解析失败（F6 回归）, Error=%q", st.Res.Error)
	}
	if st.Res.ConclusionText != "fine" {
		t.Errorf("合法结论文本应保留, 得 %q", st.Res.ConclusionText)
	}
	if len(st.Res.Risks) != 0 {
		t.Errorf("错型元素应被跳过不编造: %+v", st.Res.Risks)
	}
}

// 转义序列（\n \t \u0000）：JSON 解码后原样持有，不炸不吞。
func TestAdvUIForgedControlChars(t *testing.T) {
	forged := "{\"check\":\"secheaders\"," +
		"\"conclusion\":{\"level\":\"fail\",\"text\":\"a\\u0000b\"}," +
		"\"risks\":[{\"level\":\"warn\",\"title\":\"line1\\nline2\",\"detail\":\"tab\\there\"}]," +
		"\"data\":{\"summary\":[\"s\\u0001x\"]}}"
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", forged)
	states := LoadBaselineProducts(repoRoot, "example.com")
	st := states[0]
	if st.Res.Error != "" {
		t.Fatalf("转义序列合法 JSON 不应解析失败: %s", st.Res.Error)
	}
	if len(st.Res.Risks) != 1 || !strings.Contains(st.Res.Risks[0].Title, "line2") {
		t.Errorf("转义多行 title 应收纳: %+v", st.Res.Risks)
	}
	if !strings.Contains(st.Res.Risks[0].Detail, "tab\there") {
		t.Errorf("转义 tab 应解码: %q", st.Res.Risks[0].Detail)
	}
	if !strings.Contains(st.Res.ConclusionText, "a\x00b") {
		t.Errorf("NUL 转义应原样解码: %q", st.Res.ConclusionText)
	}
}

// ── 3. 巨型伪造文件：8MB 级合法 JSON 全量载入（记录内存放大，不崩） ──

func TestAdvUIForgedBigFile(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"check":"secheaders","conclusion":{"level":"warn","text":"forged"},"risks":[`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"level":"warn","title":"risk-` + strings.Repeat("r", 200) + `","detail":"` + strings.Repeat("d", 200) + `"}`)
	}
	b.WriteString(`],"data":{"summary":["` + strings.Repeat("s", 100000) + `"]}}`)
	repoRoot := t.TempDir()
	writeBaselineFixture(t, repoRoot, "example.com", "secheaders", b.String())
	if fi, err := os.Stat(filepath.Join(outDirFor(repoRoot, "example.com"), "secheaders.json")); err != nil || fi.Size() < 4<<20 {
		t.Fatalf("fixture 未写入: %v", err)
	}
	states := LoadBaselineProducts(repoRoot, "example.com")
	st := states[0]
	if len(st.Res.Risks) != 20000 {
		t.Errorf("2 万条伪造风险应全量载入, 得 %d", len(st.Res.Risks))
	}
	if len(st.Res.RawJSON) < 4<<20 {
		t.Error("RawJSON 应持有全文（卡片原始 JSON 展示契约）")
	}
	rows := BaselineConclusionRows(states)
	if len(rows) != 8 {
		t.Errorf("结论行应 8 行, 得 %d", len(rows))
	}
}

// ── 4. 事件流伪造：未知 module/重复事件/未知事件名 ──

func TestAdvUIEventStatesForged(t *testing.T) {
	evs := []store.ProgressEvent{
		{Event: "start", Module: "pipeline"},
		{Event: "start", Module: "baseline"},
		{Event: "start", Module: "secheaders"},
		{Event: "done", Module: "secheaders"},
		{Event: "fail", Module: "secheaders"}, // 同名取最后
		{Event: "start", Module: "not-a-check"},
		{Event: "bogus-event", Module: "webfiles"},
	}
	out := baselineEventStates(evs)
	if out["secheaders"] != "fail" {
		t.Errorf("同名事件应取最后, 得 %q", out["secheaders"])
	}
	if _, ok := out["not-a-check"]; ok {
		t.Error("未知 module 不应入表")
	}
	if _, ok := out["webfiles"]; ok {
		t.Error("未知事件名不应入表")
	}
	if _, ok := out["baseline"]; ok {
		t.Error("任务级 module=baseline 不应入表")
	}
	// 相位合成：事件压产物
	st := BaselineCheckState{Key: "secheaders", Loaded: true, Res: BaselineResult{ConclusionLevel: "ok"}}
	if ph := baselineCheckPhase(st, "running", true); ph != "running" {
		t.Errorf("running 应压过产物, 得 %s", ph)
	}
	if ph := baselineCheckPhase(BaselineCheckState{Key: "x"}, "", true); ph != "queued" {
		t.Errorf("无产物+运行中应 queued, 得 %s", ph)
	}
	if ph := baselineCheckPhase(BaselineCheckState{Key: "x", Loaded: true, Res: BaselineResult{Error: "boom"}}, "done", false); ph != "failed" {
		t.Errorf("error 产物+done 应 failed, 得 %s", ph)
	}
}
