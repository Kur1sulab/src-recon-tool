package engine

// fix2b_test.go — Stop 先于 Start 到达时（created 窗口/竞态），Start 必须自检
// 放弃：否则 hStop 已把任务落 stopped，Start 照常跑完，停止被静默吞掉。
// 语义自旧 runner.go:317-323 平移（进程内执行器同闸）。

import (
	"testing"
	"time"
)

func TestStopBeforeStartAbortsLaunch(t *testing.T) {
	r, _ := newTestRunner(t)
	// 进程表无此 id 时 Stop 返回 ErrNotRunning，但必须留下"已请求停止"旗标
	if err := r.Stop("t-race"); err == nil {
		t.Fatal("未启动任务 Stop 应返回错误（ErrNotRunning 语义）")
	}
	if r.IsRunning("t-race") {
		t.Fatal("任务未启动不应在运行态")
	}
	err := r.Start("t-race", "icp", "xycovo.com", nil)
	if err == nil {
		t.Fatal("已请求停止的任务 Start 应自检放弃，不得照常执行")
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.IsRunning("t-race") {
		if time.Now().After(deadline) {
			t.Fatal("Start 放弃后不应留下运行中的任务")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 防回归：正常 Start 不受旗标残留影响（无 Stop 时照常跑）。
func TestStartWithoutStopStillWorks(t *testing.T) {
	r, sink := newTestRunner(t)
	if err := r.Start("t-normal", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !r.IsRunning("t-normal") {
		t.Fatal("正常 Start 应进入运行态")
	}
	_ = r.Stop("t-normal")
	waitTerminal(t, sink, "t-normal")
}
