package engine

// fix1_test.go — 第 1 轮修复回归：
//   1. ResolvePython 跳过 Windows 商店占位程序（WindowsApps 存根探测可通过但运行必败）
//   2. 进程已退出后的 Stop / killTree 应幂等（此前并发双杀报 409 "invalid argument"）

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestResolvePythonSkipsWindowsAppsStub(t *testing.T) {
	r := NewRunner(t.TempDir(), t.TempDir(), "")
	r.LookPath = func(name string) (string, error) {
		if name == "python" {
			return `C:\Users\x\AppData\Local\Microsoft\WindowsApps\python.exe`, nil
		}
		if name == "python3" {
			return `C:\Program Files\Python\python3.exe`, nil
		}
		t.Fatalf("不应探测 %s", name)
		return "", exec.ErrNotFound
	}
	p, err := r.ResolvePython()
	if err != nil {
		t.Fatalf("ResolvePython: %v", err)
	}
	if p != `C:\Program Files\Python\python3.exe` {
		t.Fatalf("应跳过 WindowsApps 存根并回退 python3, 得 %q", p)
	}
}

func TestResolvePythonAllStubsFails(t *testing.T) {
	r := NewRunner(t.TempDir(), t.TempDir(), "")
	r.LookPath = func(name string) (string, error) {
		return `C:\Users\x\AppData\Local\Microsoft\WindowsApps\` + name + ".exe", nil
	}
	if _, err := r.ResolvePython(); err == nil {
		t.Fatal("全部命中 WindowsApps 存根时应报错，而不是返回存根路径")
	}
}

func TestStopAfterProcessExitIsIdempotent(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "exit", "/b", "0") // 立即退出
	}
	r.SetSink(newFakeSink())
	if err := r.Start("t-exit", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for r.IsRunning("t-exit") {
		if time.Now().After(deadline) {
			t.Fatal("假进程 8 秒未退出")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 进程已被监视 goroutine 摘除：Stop 应返回可识别的 ErrNotRunning（调用方按幂等成功处理）
	err := r.Stop("t-exit")
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("已退出任务 Stop 应返回 ErrNotRunning, 得 %v", err)
	}
}

func TestKillTreeOnExitedProcessIsNil(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	c := exec.Command("cmd", "/c", "exit", "/b", "0")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait() // 进程已退出
	if err := killTree(c); err != nil {
		t.Fatalf("对已退出进程 killTree 应幂等返回 nil, 得 %v", err)
	}
}
