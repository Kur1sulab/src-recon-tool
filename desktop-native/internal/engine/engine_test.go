package engine

// engine_test.go — 直调重写后的 Runner 行为回归（进程内执行器，零子进程）：
//   - 模块白名单收缩为八模块（jsintel/portscan 随全集成退役）；
//   - 每任务进度事件契约：pipeline_start → start(cmd) → 引擎内层事件 →
//     done|fail(cmd) → pipeline_end(done|fail)，即 store.ProgressEvent 直达 sink；
//   - Stop = context 取消，job goroutine 判 ctx 落 stopped；
//   - StopAll 收尾路径、RunningIDs/IsRunning 语义保留。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"recon-native/internal/store"
)

// ── 模块白名单 ──

func TestCmdAllowedEightModules(t *testing.T) {
	allowed := []string{"all", "paths", "api", "fingerprint", "subdomain", "reverse", "icp", "baseline"}
	for _, c := range allowed {
		if !CmdAllowed(c) {
			t.Fatalf("%s 应在八模块白名单内", c)
		}
	}
	for _, c := range []string{"jsintel", "portscan", "poc", "verify", "llm"} {
		if CmdAllowed(c) {
			t.Fatalf("%s 不在白名单内（jsintel/portscan 已退役，其余从未开放）", c)
		}
	}
}

// ── 假件：sink 记录回调 + 模块函数表注入桩 ──

type fakeSink struct {
	mu     sync.Mutex
	events map[string][]store.ProgressEvent
	status map[string]string
}

func newFakeSink() *fakeSink {
	return &fakeSink{events: map[string][]store.ProgressEvent{}, status: map[string]string{}}
}

func (f *fakeSink) AppendProgress(id string, evs []store.ProgressEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[id] = append(f.events[id], evs...)
}

func (f *fakeSink) SetStatus(id, status string, _ *int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = status
}

func (f *fakeSink) eventsOf(id string) []store.ProgressEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.ProgressEvent(nil), f.events[id]...)
}

func (f *fakeSink) statusOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id]
}

// blockUntilCancel 模块桩：阻塞到 Stop 取消才返回（测停止路径）。
func blockUntilCancel(ctx context.Context, _ string, _ string, _ []string) error {
	<-ctx.Done()
	return ctx.Err()
}

// newTestRunner 造一个八模块全注入桩的 runner（桩=阻塞到取消，零外网零落盘）。
func newTestRunner(t *testing.T) (*Runner, *fakeSink) {
	t.Helper()
	r := NewRunner(t.TempDir())
	sink := newFakeSink()
	r.SetSink(sink)
	for _, c := range []string{"all", "paths", "api", "fingerprint", "subdomain", "reverse", "icp", "baseline"} {
		r.SetModuleFunc(c, blockUntilCancel)
	}
	return r, sink
}

// waitTerminal 等任务落终态并返回终态（Start/Stop 异步收尾，与旧 monitor 等待同式）。
func waitTerminal(t *testing.T, sink *fakeSink, id string) string {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		if st := sink.statusOf(id); st == store.StatusDone || st == store.StatusFail || st == store.StatusStopped {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("8 秒未到终态，当前 %q", sink.statusOf(id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ── 事件序列与终态 ──

func TestStartEmitsEventSequenceOnSuccess(t *testing.T) {
	r, sink := newTestRunner(t)
	var gotTarget string
	r.SetModuleFunc("icp", func(_ context.Context, _, target string, _ []string) error {
		gotTarget = target
		return nil
	})
	if err := r.Start("t1", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminal(t, sink, "t1"); st != store.StatusDone {
		t.Fatalf("应落 done，得 %q", st)
	}
	if gotTarget != "xycovo.com" {
		t.Fatalf("模块应收到归一化目标，得 %q", gotTarget)
	}
	want := []store.ProgressEvent{
		{Module: "pipeline", Event: "pipeline_start", Detail: "icp"},
		{Module: "icp", Event: "start"},
		{Module: "icp", Event: "done"},
		{Module: "pipeline", Event: "pipeline_end", Detail: "done"},
	}
	evs := sink.eventsOf("t1")
	if len(evs) != len(want) {
		t.Fatalf("事件数 %d，期望 %d：%+v", len(evs), len(want), evs)
	}
	for i, w := range want {
		if evs[i].Module != w.Module || evs[i].Event != w.Event || evs[i].Detail != w.Detail {
			t.Fatalf("事件[%d] = %+v，期望 %+v", i, evs[i], w)
		}
	}
}

func TestStartModuleErrorFails(t *testing.T) {
	r, sink := newTestRunner(t)
	r.SetModuleFunc("paths", func(context.Context, string, string, []string) error {
		return errors.New("写盘失败")
	})
	if err := r.Start("t1", "paths", "http://127.0.0.1:8799/real", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminal(t, sink, "t1"); st != store.StatusFail {
		t.Fatalf("模块报错应落 fail，得 %q", st)
	}
	evs := sink.eventsOf("t1")
	last, prev := evs[len(evs)-1], evs[len(evs)-2]
	if last.Module != "pipeline" || last.Event != "pipeline_end" || last.Detail != "fail" {
		t.Fatalf("收尾事件应为 pipeline_end fail: %+v", last)
	}
	if prev.Module != "paths" || prev.Event != "fail" || prev.Detail != "写盘失败" {
		t.Fatalf("模块失败事件应带错误详情: %+v", prev)
	}
}

// all 契约（recon.py:250-256 / cli.go:98）：无模块级 start/done，只有
// pipeline_start / 步骤级事件 / pipeline_end。步骤级事件由 allrunner 发。
func TestStartAllHasNoModuleLevelEvents(t *testing.T) {
	r, sink := newTestRunner(t)
	r.SetModuleFunc("all", func(context.Context, string, string, []string) error { return nil }) // 快速完成桩
	if err := r.Start("t1", "all", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitTerminal(t, sink, "t1")
	evs := sink.eventsOf("t1")
	if len(evs) == 0 {
		t.Fatal("应有事件")
	}
	first, last := evs[0], evs[len(evs)-1]
	if first.Module != "pipeline" || first.Event != "pipeline_start" || first.Detail != "all" {
		t.Fatalf("首事件应为 pipeline_start all: %+v", first)
	}
	if last.Event != "pipeline_end" || last.Detail != "done" {
		t.Fatalf("末事件应为 pipeline_end done: %+v", last)
	}
	for _, ev := range evs[1 : len(evs)-1] {
		if ev.Module == "all" {
			t.Fatalf("all 无模块级事件，混入 %+v", ev)
		}
	}
}

// ── 停止语义 ──

func TestStartStopCancelsModule(t *testing.T) {
	r, sink := newTestRunner(t)
	cancelSeen := make(chan struct{})
	r.SetModuleFunc("subdomain", func(ctx context.Context, _, _ string, _ []string) error {
		<-ctx.Done()
		close(cancelSeen)
		return ctx.Err()
	})
	if err := r.Start("t1", "subdomain", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Stop("t1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-cancelSeen: // 取消已传播进模块函数（RunContext 同一 ctx）
	case <-time.After(5 * time.Second):
		t.Fatal("Stop 未把取消传播进模块函数")
	}
	if st := waitTerminal(t, sink, "t1"); st != store.StatusStopped {
		t.Fatalf("停止后应落 stopped，得 %q", st)
	}
	evs := sink.eventsOf("t1")
	last := evs[len(evs)-1]
	if last.Event != "pipeline_end" || last.Detail != "fail" {
		t.Fatalf("停止应收尾 pipeline_end fail: %+v", last)
	}
	if r.IsRunning("t1") {
		t.Fatal("收尾后不应仍在运行态")
	}
}

func TestStopUnknownIDErrNotRunning(t *testing.T) {
	r, _ := newTestRunner(t)
	if err := r.Stop("no-such"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("未运行任务 Stop 应返回 ErrNotRunning，得 %v", err)
	}
	// 幂等：重复 Stop 同样 ErrNotRunning，不 panic
	if err := r.Stop("no-such"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("重复 Stop 应幂等，得 %v", err)
	}
}

func TestStartDuplicateRejected(t *testing.T) {
	r, sink := newTestRunner(t)
	if err := r.Start("t1", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Start("t1", "icp", "xycovo.com", nil); err == nil || !strings.Contains(err.Error(), "已在运行") {
		t.Fatalf("重复 Start 应报「任务已在运行」，得 %v", err)
	}
	_ = r.Stop("t1")
	waitTerminal(t, sink, "t1")
}

func TestStartRejectsRetiredCmd(t *testing.T) {
	r, _ := newTestRunner(t)
	if err := r.Start("t1", "jsintel", "http://127.0.0.1:8799/real", nil); err == nil {
		t.Fatal("jsintel 已退役，Start 应拒绝")
	}
	if err := r.Start("t1", "portscan", "47.100.49.228", nil); err == nil {
		t.Fatal("portscan 已退役，Start 应拒绝")
	}
}

// ── StopAll 收尾 / 运行态查询 ──

func TestStopAllCancelsAllJobs(t *testing.T) {
	r, sink := newTestRunner(t)
	for _, id := range []string{"a1", "a2", "a3"} {
		if err := r.Start(id, "icp", "xycovo.com", nil); err != nil {
			t.Fatalf("Start(%s): %v", id, err)
		}
	}
	if n := len(r.RunningIDs()); n != 3 {
		t.Fatalf("运行态应 3 个任务，得 %d", n)
	}
	r.StopAll()
	for _, id := range []string{"a1", "a2", "a3"} {
		if st := waitTerminal(t, sink, id); st != store.StatusStopped {
			t.Fatalf("%s 应落 stopped，得 %q", id, st)
		}
	}
	if n := len(r.RunningIDs()); n != 0 {
		t.Fatalf("StopAll 后运行态应清空，得 %v", r.RunningIDs())
	}
}
