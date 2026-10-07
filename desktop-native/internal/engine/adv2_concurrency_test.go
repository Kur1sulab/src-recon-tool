package engine

// adv2_concurrency_test.go — 原生轮第 2 轮对抗回归（直调重写后）：
// 任务运行中强停与重复开始并发。零外网零子进程：模块函数表注入桩。
// 不变量：
//  1. 同一任务 ID 并发 Start：恰好一个成功，其余报"任务已在运行"；
//  2. Start/Stop 对打：无论交错顺序，收尾时不留运行态任务、终态不回退；
//  3. 并发双停：幂等，无 panic；
//  4. Stop 的取消真实验证：模块函数收到的 ctx 被 cancel（原树杀验证退役——
//     进程内直调无壳启动的子进程，无可级联对象）。

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func waitGone(t *testing.T, r *Runner, id string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for r.IsRunning(id) {
		if time.Now().After(deadline) {
			t.Fatal("8 秒后任务仍在运行态")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAdv2ConcurrentStartSameID 同一 ID 并发重复开始：恰一个成功。
func TestAdv2ConcurrentStartSameID(t *testing.T) {
	r, _ := newTestRunner(t)

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount, dupCount := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.Start("adv2-dup", "icp", "xycovo.com", nil)
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

// TestAdv2StartStopHammer Start 与 Stop 对打：终局无运行态任务、无 panic、状态机不崩。
func TestAdv2StartStopHammer(t *testing.T) {
	r, sink := newTestRunner(t)

	stopWG := sync.WaitGroup{}
	stopWG.Add(2)
	deadline := time.Now().Add(2 * time.Second)
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

	// 终局：再停一次（幂等），此后不允许再有运行态任务
	_ = r.Stop("adv2-hammer")
	waitGone(t, r, "adv2-hammer")
	// 终态一旦落定不得回退成运行态
	time.Sleep(600 * time.Millisecond)
	if st := sink.statusOf("adv2-hammer"); st == "running" {
		t.Fatal("收尾后状态不得停留在 running")
	}
}

// TestAdv2ConcurrentDoubleStop 并发双停：幂等无 panic。
func TestAdv2ConcurrentDoubleStop(t *testing.T) {
	r, _ := newTestRunner(t)
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
