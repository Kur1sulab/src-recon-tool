package toolrun

// fix2b_test.go — RunSubfinder 必须真正消费 timeout（CommandContext）：
// 卡死的 subfinder 不得无限阻塞子域收集流程。

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRunSubfinderTimeoutAborts(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过真实子进程用例")
	}
	if _, err := exec.LookPath("cmd"); err != nil {
		t.Skip("仅 Windows")
	}
	dir := t.TempDir()
	// 假 subfinder：睡 5 秒（ping 本机回环，零外网）
	stub := filepath.Join(dir, "subfinder.cmd")
	if err := os.WriteFile(stub, []byte("@echo off\r\nping -n 6 127.0.0.1 -w 1000 >nul\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	subs, err := RunSubfinder(stub, "stub.example", 300*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("timeout 未生效：RunSubfinder 阻塞了 %v（应 ~300ms 返回）", elapsed)
	}
	if err == nil && len(subs) > 0 {
		t.Fatalf("超时应报错或返回空, 得 %v", subs)
	}
}

func TestRunSubfinderEmptyPathNoop(t *testing.T) {
	if subs, err := RunSubfinder("", "x.example", time.Second); subs != nil || err != nil {
		t.Fatalf("空 path 应 no-op 返回 nil,nil, 得 %v,%v", subs, err)
	}
}

// home 侧内联清洗回归：含 ".." 悬浮组件的 ONEFORALL_HOME 配置被清洗为
// 不存在的目录 → 直接返回 nil（不执行任何工具、不读任何越界路径）。
func TestRunOneForAllRejectsTraversalHome(t *testing.T) {
	if got := RunOneForAll(`..\..\..`, "a.com", t.TempDir(), time.Second); got != nil {
		t.Fatalf("穿越形态 home 应返回 nil, 得 %v", got)
	}
	if got := RunOneForAll("  ", "a.com", t.TempDir(), time.Second); got != nil {
		t.Fatalf("空白 home 应返回 nil, 得 %v", got)
	}
}
