package ui

// baseline_page_test.go — 六页改造与基线仪表盘页的可测纯函数：
//   - 六页路由：pageBaseline 常量、pageNames 长度、Ctrl+数字派生（写死 5 的回归位）；
//   - 基线任务进度事件 → 每检查运行态；产品态 × 运行态 → 卡片显示相位。

import (
	"testing"

	"gioui.org/widget"
	"recon-native/internal/store"
)

func TestSixPageRouting(t *testing.T) {
	if len(pageNames) != 6 {
		t.Fatalf("应有六页, 得 %d", len(pageNames))
	}
	if pageBaseline != 5 {
		t.Fatalf("pageBaseline 应为 5, 得 %d", pageBaseline)
	}
	if pageNames[pageBaseline] != "暴露面" {
		t.Fatalf("第六页名 = %q", pageNames[pageBaseline])
	}
	// Ctrl+数字键位按页数派生（此前写死 1..5，六页改造的回归位）
	keys := pageKeyNames()
	if len(keys) != 6 {
		t.Fatalf("键位应派生为 6 个, 得 %v", keys)
	}
	for i, k := range keys {
		if k != string(rune('1'+i)) {
			t.Fatalf("键位[%d] = %q", i, k)
		}
	}
	// applyPageKey 路由
	a := &appUI{}
	if !a.applyPageKey("6") || a.page != pageBaseline {
		t.Fatalf("Ctrl+6 应切到基线页, page=%d", a.page)
	}
	if !a.applyPageKey("1") || a.page != pageDashboard {
		t.Fatalf("Ctrl+1 应切到仪表盘, page=%d", a.page)
	}
	if a.applyPageKey("7") {
		t.Fatal("越界键位应拒绝且不切页")
	}
	if a.page != pageDashboard {
		t.Fatalf("拒绝后页不应变, page=%d", a.page)
	}
	// 侧栏导航项按页数派生
	a2 := &appUI{navBtns: make([]widget.Clickable, len(pageNames))}
	if n := len(navItems(a2)); n != 6 {
		t.Fatalf("侧栏导航项应 6 个, 得 %d", n)
	}
}

func TestBaselineEventStates(t *testing.T) {
	evs := []store.ProgressEvent{
		{Module: "pipeline", Event: "pipeline_start", Detail: "baseline"},
		{Module: "baseline", Event: "start"},
		{Module: "secheaders", Event: "start"},
		{Module: "secheaders", Event: "done"},
		{Module: "webfiles", Event: "start"},
		{Module: "mailsec", Event: "fail", Detail: "DNS 超时"},
		{Module: "archives", Event: "skipped", Detail: "总预算耗尽"},
	}
	got := baselineEventStates(evs)
	want := map[string]string{
		"secheaders": "done", "webfiles": "running",
		"mailsec": "fail", "archives": "skipped",
	}
	if len(got) != len(want) {
		t.Fatalf("态数 = %d (%v), 期望 %v", len(got), got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s 态 = %q, 期望 %q", k, got[k], w)
		}
	}
	// 同名事件取最后一条（重跑场景）
	got2 := baselineEventStates([]store.ProgressEvent{
		{Module: "whois", Event: "fail"},
		{Module: "whois", Event: "done"},
	})
	if got2["whois"] != "done" {
		t.Fatalf("同名事件应取最后一条, 得 %q", got2["whois"])
	}
	// 任务级事件不进每检查态
	got3 := baselineEventStates([]store.ProgressEvent{
		{Module: "baseline", Event: "start"},
		{Module: "baseline", Event: "done"},
	})
	if len(got3) != 0 {
		t.Fatalf("任务级事件不应入每检查态: %v", got3)
	}
}

func TestBaselineCheckPhase(t *testing.T) {
	loaded := BaselineCheckState{Key: "secheaders", Loaded: true, Res: BaselineResult{ConclusionLevel: "warn"}}
	failed := BaselineCheckState{Key: "webfiles", Loaded: true, Res: BaselineResult{Error: "超时"}}
	empty := BaselineCheckState{Key: "dnsrec"}

	cases := []struct {
		name    string
		st      BaselineCheckState
		ev      string
		taskRun bool
		want    string
	}{
		{"运行事件压过旧产物", loaded, "running", true, "running"},
		{"产物结论", loaded, "done", false, "conclusion"},
		{"产物失败态", failed, "done", false, "failed"},
		{"产物失败态·无事件(历史)", failed, "", false, "failed"},
		{"跳过", empty, "skipped", true, "skipped"},
		{"排队中", empty, "", true, "queued"},
		{"未运行", empty, "", false, "notrun"},
	}
	for _, c := range cases {
		if got := baselineCheckPhase(c.st, c.ev, c.taskRun); got != c.want {
			t.Fatalf("[%s] phase = %q, 期望 %q", c.name, got, c.want)
		}
	}
	// 相位 → 中文与配色族齐全（不崩、不空）
	for _, ph := range []string{"notrun", "queued", "running", "skipped", "conclusion", "failed"} {
		if baselinePhaseLabel(ph) == "" {
			t.Fatalf("相位 %s 应有中文标签", ph)
		}
	}
}
