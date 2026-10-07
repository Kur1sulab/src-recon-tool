package engine

// inproc_integration_test.go — 直调执行器 × engine-go/mockweb 假站集成：
// 真模块函数表 + httptest 本地靶站（127.0.0.1，零外网），验证
// Start → 模块直调 → 事件直通 sink → 产物落盘 → 终态 的完整链路。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/cli"
	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"

	"recon-native/internal/store"
)

// waitTerminalFor 等指定任务落终态（集成测试用长一点的上限：真引擎跑网络循环）。
func waitTerminalFor(t *testing.T, sink *fakeSink, id string, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if st := sink.statusOf(id); st == store.StatusDone || st == store.StatusFail || st == store.StatusStopped {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s 未在 %s 内到终态，当前 %q", id, d, sink.statusOf(id))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func containsTuple(evs []store.ProgressEvent, module, event string) bool {
	for _, ev := range evs {
		if ev.Module == module && ev.Event == event {
			return true
		}
	}
	return false
}

// TestIntegrationAPIAgainstMockweb api 模块全链路：真 apiunauth 打本地假站，
// 事件契约与产物落盘一次验完。
func TestIntegrationAPIAgainstMockweb(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	repo := t.TempDir()
	r := NewRunner(repo)
	sink := newFakeSink()
	r.SetSink(sink)

	target := srv.URL + "/real"
	if err := r.Start("t-api", "api", target, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminalFor(t, sink, "t-api", 60*time.Second); st != store.StatusDone {
		t.Fatalf("本地假站上的 api 任务应完成，得 %q；事件=%+v", st, sink.eventsOf("t-api"))
	}
	evs := sink.eventsOf("t-api")
	for _, want := range [][2]string{
		{"pipeline", "pipeline_start"}, {"api", "start"}, {"api", "done"}, {"pipeline", "pipeline_end"},
	} {
		if !containsTuple(evs, want[0], want[1]) {
			t.Fatalf("缺事件 %v：%+v", want, evs)
		}
	}
	// 产物目录按三方同名规则落盘且非空
	outDir := filepath.Join(repo, "out", cli.OutdirName(target))
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("产物目录应存在: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("产物目录不应为空")
	}
}

// TestIntegrationBaselineAgainstMockweb baseline 模块全链路：--checks 过滤 +
// PickBase 接缝注入 + 逐检查事件直通 sink + 逐检查产物落盘。
func TestIntegrationBaselineAgainstMockweb(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	repo := t.TempDir()
	r := NewRunner(repo)
	r.pickBase = func(string) string { return srv.URL + "/sec" } // 本地靶站入口（生产走 cli.PickBase）
	sink := newFakeSink()
	r.SetSink(sink)

	if err := r.Start("t-base", "baseline", "secexample.invalid", []string{"--checks", "secheaders,webfiles"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminalFor(t, sink, "t-base", 90*time.Second); st != store.StatusDone {
		t.Fatalf("本地假站上的 baseline 任务应完成，得 %q；事件=%+v", st, sink.eventsOf("t-base"))
	}
	raw := sink.eventsOf("t-base")
	// 首尾契约
	if raw[0].Module != "pipeline" || raw[0].Event != "pipeline_start" || raw[0].Detail != "baseline" {
		t.Fatalf("首事件不符: %+v", raw[0])
	}
	last := raw[len(raw)-1]
	if last.Event != "pipeline_end" || last.Detail != "done" {
		t.Fatalf("末事件不符: %+v", last)
	}
	// 逐检查事件直通 sink（NormalizeChecks 按序：secheaders → webfiles）
	var order []string
	for _, ev := range raw {
		if ev.Event == "start" && (ev.Module == "secheaders" || ev.Module == "webfiles") {
			order = append(order, ev.Module)
		}
	}
	if len(order) != 2 || order[0] != "secheaders" || order[1] != "webfiles" {
		t.Fatalf("逐检查 start 序列应为 secheaders,webfiles，得 %v", order)
	}
	for _, c := range []string{"secheaders", "webfiles"} {
		found := false
		for _, ev := range raw {
			if ev.Module == c && ev.Event == "done" {
				found = true
			}
		}
		if !found {
			t.Fatalf("检查 %s 缺 done 事件：%+v", c, raw)
		}
	}
	// 逐检查产物落盘（结果页/暴露面页的数据源）
	outDir := filepath.Join(repo, "out", cli.OutdirName("secexample.invalid"))
	for _, f := range []string{"secheaders.json", "webfiles.json"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Fatalf("产物 %s 应落盘: %v", f, err)
		}
	}
}

// TestIntegrationAllDomainBranchSkipsRetiredSteps all 模块（域名分支）在本地
// 假站上走通：退役步骤（jsintel/portscan）发 skipped 事件而非中断，report 收尾。
func TestIntegrationAllDomainBranchSkipsRetiredSteps(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	repo := t.TempDir()
	r := NewRunner(repo)
	r.pickBase = func(string) string { return srv.URL + "/fppage" }
	sink := newFakeSink()
	r.SetSink(sink)

	if err := r.Start("t-all", "all", "secexample.invalid", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminalFor(t, sink, "t-all", 120*time.Second); st != store.StatusDone {
		t.Fatalf("本地假站上的 all 任务应完成，得 %q；事件=%+v", st, sink.eventsOf("t-all"))
	}
	raw := sink.eventsOf("t-all")
	// skipped 事件：detail=未随全集成版提供
	skipped := map[string]string{}
	for _, ev := range raw {
		if ev.Event == "skipped" {
			skipped[ev.Module] = ev.Detail
		}
	}
	for _, m := range []string{"jsintel", "portscan"} {
		if !strings.Contains(skipped[m], "未随全集成版提供") {
			t.Fatalf("%s 应有 skipped 事件（detail=未随全集成版提供），得 %q", m, skipped[m])
		}
	}
	// 域名分支步骤序列出现：subdomain → verify → … → report
	seen := map[string]bool{}
	for _, ev := range raw {
		if ev.Event == "start" {
			seen[ev.Module] = true
		}
	}
	for _, m := range []string{"subdomain", "verify", "asset", "icp", "fingerprint", "paths", "api", "report"} {
		if !seen[m] {
			t.Fatalf("域名分支缺步骤 start 事件：%s（全部=%+v）", m, raw)
		}
	}
	if last := raw[len(raw)-1]; last.Event != "pipeline_end" || last.Detail != "done" {
		t.Fatalf("末事件应为 pipeline_end done: %+v", last)
	}
}
