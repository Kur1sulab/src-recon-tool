package engine

// adv2_concurrency_test.go — 原生轮第 2 轮对抗：任务运行中强杀与重复开始并发。
// 零外网：假进程用本机 cmd ping 自环，真进程树杀用 taskkill（本机进程，无网络行为）。
// 不变量：
//  1. 同一任务 ID 并发 Start：恰好一个成功，其余报"任务已在运行"；
//  2. Start/Stop 对打：无论交错顺序，收尾时不留活进程、终态不回退；
//  3. 并发双停：幂等，无 panic；
//  4. Stop 的树杀真实验证：进程树里没有存活成员。

import (
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func slowProcess() *exec.Cmd {
	return exec.Command("cmd", "/c", "ping", "-n", "30", "127.0.0.1", "-w", "1000", ">nul")
}

func waitGone(t *testing.T, r *Runner, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.IsRunning(id) {
		if time.Now().After(deadline) {
			t.Fatal("10 秒后任务仍在运行态")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAdv2ConcurrentStartSameID 同一 ID 并发重复开始：恰一个成功。
func TestAdv2ConcurrentStartSameID(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd { return slowProcess() }
	r.SetSink(newFakeSink())

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount, dupCount := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.Start("adv2-dup", "portscan", "47.100.49.228", nil)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okCount++
			case strings.Contains(err.Error(), "已在运行"):
				dupCount++
			default:
				t.Errorf("并发 Start 得到意外错误: %v", err)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("并发 16 次同 ID Start 应恰 1 次成功，得 %d 成功 / %d 重复拒绝", okCount, dupCount)
	}
	_ = r.Stop("adv2-dup")
	waitGone(t, r, "adv2-dup")
}

// TestAdv2StartStopHammer Start 与 Stop 对打：终局无活进程、无 panic、状态机不崩。
func TestAdv2StartStopHammer(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd { return slowProcess() }
	sink := newFakeSink()
	r.SetSink(sink)

	stopWG := sync.WaitGroup{}
	stopWG.Add(2)
	deadline := time.Now().Add(3 * time.Second)
	go func() { // 打手 A：反复起
		defer stopWG.Done()
		for time.Now().Before(deadline) {
			_ = r.Start("adv2-hammer", "icp", "xycovo.com", nil)
			time.Sleep(10 * time.Millisecond)
		}
	}()
	go func() { // 打手 B：反复停
		defer stopWG.Done()
		for time.Now().Before(deadline) {
			_ = r.Stop("adv2-hammer")
			time.Sleep(10 * time.Millisecond)
		}
	}()
	stopWG.Wait()

	// 终局：再停一次（幂等），此后不允许再有活进程
	_ = r.Stop("adv2-hammer")
	waitGone(t, r, "adv2-hammer")
	// 终态一旦落定不得回退成运行态
	time.Sleep(600 * time.Millisecond)
	if st := sink.status["adv2-hammer"]; st == "running" {
		t.Fatal("收尾后状态不得停留在 running")
	}
}

// TestAdv2ConcurrentDoubleStop 并发双停：幂等无 panic，进程树全灭。
func TestAdv2ConcurrentDoubleStop(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd { return slowProcess() }
	r.SetSink(newFakeSink())
	if err := r.Start("adv2-2stop", "paths", "http://127.0.0.1:8799/real", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.Stop("adv2-2stop") // 错误允许：ErrNotRunning / nil 都算幂等成功
		}()
	}
	wg.Wait()
	waitGone(t, r, "adv2-2stop")
}

// TestAdv2TreeKillLeavesNoAliveMember 树杀实证：Start 起的 cmd（真 ping 子进程）
// 被 Stop 后，进程名里不再有该 cmd 的存活成员。用 tasklist 数 ping 存量做旁证。
func TestAdv2TreeKillLeavesNoAliveMember(t *testing.T) {
	if !isWindows() {
		t.Skip("仅 Windows")
	}
	countPing := func() int {
		out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq ping.exe", "/FO", "CSV", "/NH").Output()
		if err != nil {
			return -1
		}
		return strings.Count(strings.ToLower(string(out)), "ping.exe") // CSV 里是大写 PING.EXE
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	// 真进程树：cmd 起 ping（cmd 是父，ping 是子，验证 /T 树杀连带）
	r.Command = func(name string, args ...string) *exec.Cmd { return slowProcess() }
	r.SetSink(newFakeSink())

	before := countPing()
	if err := r.Start("adv2-treekill", "portscan", "47.100.49.228", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(1500 * time.Millisecond) // 让 ping 子进程起来
	during := countPing()
	if err := r.Stop("adv2-treekill"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	waitGone(t, r, "adv2-treekill")
	time.Sleep(500 * time.Millisecond)
	after := countPing()
	if during <= before {
		t.Fatalf("停前应能观察到 ping 子进程存量上升，before=%d during=%d", before, during)
	}
	if after > before {
		t.Fatalf("树杀后 ping 存量应回落，before=%d after=%d（有漏杀成员）", before, after)
	}
}
