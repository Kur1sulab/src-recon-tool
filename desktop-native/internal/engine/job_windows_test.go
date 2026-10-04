//go:build windows

package engine

// Job Object 语义实证（对抗 P2 的修复回归）：挂入 Job 的进程树在 Job
// 句柄关闭时整树终局（JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE）——壳被硬杀
// （句柄随进程回收）不再留孤儿扫描。真 cmd→ping 树 + tasklist 全局存量
// 旁证，手法与 adv2 树杀实验一致（零外网，ping 本机回环）。

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func pingProcCount(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq PING.EXE", "/FO", "CSV", "/NH").CombinedOutput()
	if err != nil {
		t.Fatalf("tasklist: %v (%s)", err, out)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "PING.EXE") {
			n++
		}
	}
	return n
}

func TestJobObjectKillsTreeOnClose(t *testing.T) {
	c := exec.Command("cmd", "/c", "ping", "-n", "30", "127.0.0.1", "-w", "1000")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	job, err := attachJob(c.Process.Pid)
	if err != nil {
		t.Skipf("宿主环境不允许挂 Job（killTree 兜底路径仍在）: %v", err)
	}
	// 等 ping 真正起来（全局存量 ≥1）
	deadline := time.Now().Add(10 * time.Second)
	for pingProcCount(t) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("挂 Job 后 ping 应已出现")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// 关句柄即整树终局
	if err := job.Close(); err != nil {
		t.Fatalf("关闭 Job 句柄: %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if pingProcCount(t) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Job 句柄关闭后 ping 应整树终局（KILL_ON_JOB_CLOSE）")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
