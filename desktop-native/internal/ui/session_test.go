package ui

import (
	"context"
	"testing"
	"time"

	"recon-native/internal/store"
)

// newTestSession 造一个可用测试会话：八模块全注入阻塞桩（阻塞到 Stop 取消，
// 零外网零落盘），真实任务库落在临时目录。
func newTestSession(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"all", "paths", "api", "fingerprint", "subdomain", "reverse", "icp", "baseline"} {
		s.Runner.SetModuleFunc(c, func(ctx context.Context, _, _ string, _ []string) error {
			<-ctx.Done()
			return ctx.Err()
		})
	}
	return s
}

func TestCreateTaskAcceptsArbitraryTarget(t *testing.T) {
	// 目标全部默认授权（用户裁定 2026-10-05）：名单概念已移除，
	// 任意格式合法的目标都应放行入库。
	s := newTestSession(t)
	id, err := s.CreateTask("evil.example.com", "paths", "")
	if err != nil {
		t.Fatalf("任意目标应默认授权放行，得错误: %v", err)
	}
	if id == "" {
		t.Fatal("放行时应返回任务 ID")
	}
	if n := len(s.Store.List()); n != 1 {
		t.Fatalf("任务应入库，得 %d 条", n)
	}
	// 格式卫生仍然生效：控制字符目标就地拒绝、不入库
	if _, err := s.CreateTask("xycovo.com\nevil", "paths", ""); err == nil {
		t.Fatal("含控制字符的目标应被拒绝")
	}
	if n := len(s.Store.List()); n != 1 {
		t.Fatalf("拒绝的任务不应入库，得 %d 条", n)
	}
}

func TestCreateTaskRejectsUnknownModule(t *testing.T) {
	s := newTestSession(t)
	if _, err := s.CreateTask("xycovo.com", "poc", ""); err == nil {
		t.Fatal("九模块之外的子命令应被拒绝")
	}
	if n := len(s.Store.List()); n != 0 {
		t.Fatalf("拒绝的任务不应入库，得 %d 条", n)
	}
}

func TestCreateTaskRejectsTargetFlagInArgs(t *testing.T) {
	s := newTestSession(t)
	if _, err := s.CreateTask("127.0.0.1:8799/real", "api", "-u http://xycovo.com"); err == nil {
		t.Fatal("可选参数里夹带目标旗标应被拒绝")
	}
	if n := len(s.Store.List()); n != 0 {
		t.Fatalf("拒绝的任务不应入库，得 %d 条", n)
	}
}

func TestCreateTaskNormalizesURLTarget(t *testing.T) {
	s := newTestSession(t)
	id, err := s.CreateTask("http://127.0.0.1:8799/real", "api", "")
	if err != nil {
		t.Fatalf("URL 目标应放行: %v", err)
	}
	got, ok := s.Store.Get(id)
	if !ok {
		t.Fatal("任务应已入库")
	}
	if got.Target != "http://127.0.0.1:8799/real" {
		t.Fatalf("url 类模块应补 http:// 前缀，得 %q", got.Target)
	}
	if got.Status != store.StatusCreated && got.Status != store.StatusRunning {
		t.Fatalf("新任务状态应为 created/running，得 %q", got.Status)
	}
}

func TestCreateTaskSubdomainRejectsURLTarget(t *testing.T) {
	s := newTestSession(t)
	if _, err := s.CreateTask("http://xycovo.com", "subdomain", ""); err == nil {
		t.Fatal("子域模块的目标应为裸域名，URL 应被拒绝")
	}
}

func TestStopTaskIdempotent(t *testing.T) {
	s := newTestSession(t)
	if _, err := s.CreateTask("xycovo.com", "icp", ""); err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	tasks := s.Store.List()
	if len(tasks) != 1 {
		t.Fatalf("应有 1 条任务，得 %d", len(tasks))
	}
	// 假进程已退出：Stop 对进程表缺失的任务按幂等成功处理
	if err := s.StopTask(tasks[0].ID); err != nil {
		t.Fatalf("进程表缺失时 Stop 应幂等成功，得 %v", err)
	}
	if err := s.StopTask("no-such-id"); err == nil {
		t.Fatal("不存在的任务应报错")
	}
}

func TestModulesEightAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Modules {
		if seen[m.Key] {
			t.Fatalf("模块 %q 重复", m.Key)
		}
		seen[m.Key] = true
		if m.Label == "" || m.Desc == "" {
			t.Fatalf("模块 %q 缺中文名或说明", m.Key)
		}
	}
	// 全集成轮（2026-10-07）：Modules 表收缩为八模块（jsintel/portscan 随
	// 全集成退役，不在表内=不可新建、无 tab），结果页 tab 与新建任务页网格随之派生。
	if len(Modules) != 8 {
		t.Fatalf("应有 8 个模块，得 %d", len(Modules))
	}
	if seen["jsintel"] || seen["portscan"] {
		t.Fatal("退役模块不得留在 Modules 表")
	}
}

// 历史任务照常展示：退役模块的中文名映射保留（老任务列表/过程行不回退英文键）。
func TestModuleLabelRetiredModulesStillLabeled(t *testing.T) {
	if got := moduleLabel("jsintel"); got != "JS 情报" {
		t.Fatalf("moduleLabel(jsintel) = %q, 期望「JS 情报」", got)
	}
	if got := moduleLabel("portscan"); got != "端口扫描" {
		t.Fatalf("moduleLabel(portscan) = %q, 期望「端口扫描」", got)
	}
}

func TestStatusTextChinese(t *testing.T) {
	cases := map[string]string{
		store.StatusCreated: "已创建",
		store.StatusRunning: "运行中",
		store.StatusDone:    "已完成",
		store.StatusFail:    "失败",
		store.StatusStopped: "已停止",
		"weird":             "weird",
	}
	for in, want := range cases {
		if got := StatusText(in); got != want {
			t.Fatalf("StatusText(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestTaskRowsNewestFirst(t *testing.T) {
	now := float64(time.Now().UnixMilli()) / 1e3
	tasks := []store.Task{
		{ID: "old", Target: "xycovo.com", Cmd: "icp", Status: store.StatusDone, CreatedAt: now - 100},
		{ID: "new", Target: "xycovo.com", Cmd: "api", Status: store.StatusRunning, CreatedAt: now},
	}
	rows := TaskRows(tasks)
	if len(rows) != 2 {
		t.Fatalf("应有 2 行，得 %d", len(rows))
	}
	if rows[0].ID != "new" || rows[1].ID != "old" {
		t.Fatalf("应按创建时间倒序，得 %v", rows)
	}
	if rows[0].Status != "运行中" || rows[1].Status != "已完成" {
		t.Fatalf("状态列应为中文，得 %+v", rows)
	}
}

func TestResultRowsFromProgress(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 15, 4, 5, 0, time.Local)
	ts := float64(t0.UnixMilli()) / 1e3
	task := store.Task{ID: "t1", Progress: []store.ProgressEvent{
		{Ts: ts, Module: "pipeline", Event: "pipeline_start", Detail: "api"},
		{Ts: ts + 1, Module: "api", Event: "start", Detail: "http://127.0.0.1:8799/real"},
		{Ts: ts + 2, Module: "api", Event: "found", Detail: "swagger /v3/api-docs"},
	}}
	rows := ResultRows(task)
	if len(rows) != 3 {
		t.Fatalf("应有 3 行，得 %d", len(rows))
	}
	if rows[0].Time != "15:04:05" {
		t.Fatalf("时间列应格式化为时分秒，得 %q", rows[0].Time)
	}
	if rows[0].Module != "流水线" || rows[2].Module != "API 面" {
		t.Fatalf("模块列应显示中文名，得 %q / %q", rows[0].Module, rows[2].Module)
	}
	if rows[2].Event != "found" || rows[2].Detail != "swagger /v3/api-docs" {
		t.Fatalf("末行字段不符: %+v", rows[2])
	}
	if got := ResultRows(store.Task{}); len(got) != 0 {
		t.Fatalf("无进度的任务应得 0 行，得 %d", len(got))
	}
}
