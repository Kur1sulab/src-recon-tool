package engine

// fix2b_test.go — Stop 先于 Start 到达时（created 窗口/竞态），Start 必须自检放弃：
// 否则 hStop 已把任务落 stopped，Start 照常起进程跑完，停止被静默吞掉。

import (
	"os/exec"
	"testing"
	"time"
)

func TestStopBeforeStartAbortsLaunch(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		// 睡 5 秒的假 python：若 Start 未自检，进程会真的起来
		return exec.Command("cmd", "/c", "ping", "-n", "6", "127.0.0.1", "-w", "1000", ">nul")
	}
	r.SetSink(newFakeSink())

	// 进程表无此 id 时 Stop 返回 ErrNotRunning，但必须留下"已请求停止"旗标
	if err := r.Stop("t-race"); err == nil {
		t.Fatal("未启动任务 Stop 应返回错误（ErrNotRunning 语义）")
	}
	if r.IsRunning("t-race") {
		t.Fatal("任务未启动不应在运行态")
	}
	err := r.Start("t-race", "portscan", "47.100.49.228", nil)
	if err == nil {
		t.Fatal("已请求停止的任务 Start 应自检放弃，不得照常起进程")
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.IsRunning("t-race") {
		if time.Now().After(deadline) {
			t.Fatal("Start 放弃后不应留下运行中的进程")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 防回归：正常 Start 不受旗标残留影响（无 Stop 时照常起）。
func TestStartWithoutStopStillWorks(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "ping", "-n", "6", "127.0.0.1", "-w", "1000", ">nul")
	}
	r.SetSink(newFakeSink())
	if err := r.Start("t-normal", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !r.IsRunning("t-normal") {
		t.Fatal("正常 Start 应进入运行态")
	}
	_ = r.Stop("t-normal")
}
