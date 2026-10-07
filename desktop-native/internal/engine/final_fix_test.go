package engine

// final_fix_test.go — 集成终修轮验收（desktop 直调执行器）：
//  1. 模块实现 panic 兜底：直调重写后模块跑在桌面主进程的 job goroutine 上，
//     任一引擎代码 panic（敌意远端数据解析路径：JSON 类型断言/切片越界/TLS
//     解析）此前会炸穿整个 exe、所有运行中任务同灭——job goroutine 单点
//     recover 就地把 panic 转 error，终态 fail、进程存活、后续任务可用。
//     all 模块的 allStep fn() 直调在 runModule 调用树内，同一兜底面覆盖。
//  2. SetModuleFunc/SetSink 导出接缝并发纪律：map/sink 读写同锁。本机无 C
//     编译器跑不了 -race（已知局限，F5 在案），此处做并发交错烟雾：
//     运行中狂调导出缝，无 fatal、任务照常收尾。
//
// 靶标全部包内注入桩（newTestRunner 桩=阻塞到取消），零网络零落盘。

import (
	"context"
	"testing"
	"time"

	"recon-native/internal/store"
)

func TestModulePanicContained(t *testing.T) {
	r, sink := newTestRunner(t)
	r.SetModuleFunc("icp", func(context.Context, string, string, []string) error {
		panic("敌意远端数据引爆模块实现")
	})
	if err := r.Start("t-panic", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// panic 被兜住 → 任务终态 fail（而不是测试进程整个死掉——改此前代码，
	// 本测试文件会以整进程 panic 崩溃的形式「失败」）
	if st := waitTerminal(t, sink, "t-panic"); st != store.StatusFail {
		t.Fatalf("panic 应转终态 fail，得 %q", st)
	}
	// 事件流照常收口：模块 fail 带异常详情 + pipeline_end fail
	evs := sink.eventsOf("t-panic")
	if len(evs) < 2 {
		t.Fatalf("panic 任务事件流应收口，实得 %+v", evs)
	}
	last, prev := evs[len(evs)-1], evs[len(evs)-2]
	if prev.Module != "icp" || prev.Event != "fail" {
		t.Fatalf("模块失败事件缺失: %+v", prev)
	}
	if last.Module != "pipeline" || last.Event != "pipeline_end" || last.Detail != "fail" {
		t.Fatalf("收尾事件应为 pipeline_end fail: %+v", last)
	}
	// 进程存活且 runner 可继续服务：下一个任务照常跑到 done
	r.SetModuleFunc("icp", func(context.Context, string, string, []string) error { return nil })
	if err := r.Start("t-after", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("panic 后同 runner 再启任务: %v", err)
	}
	if st := waitTerminal(t, sink, "t-after"); st != store.StatusDone {
		t.Fatalf("panic 后续任务应照常 done，得 %q", st)
	}
}

func TestSetSinkSetModuleConcurrentSmoke(t *testing.T) {
	r, sink := newTestRunner(t)
	// 目标模块桩：睡 30ms 后成功（给导出缝并发写留出交错窗口）
	r.SetModuleFunc("icp", func(ctx context.Context, _, _ string, _ []string) error {
		select {
		case <-time.After(30 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	stop := make(chan struct{})
	done := make(chan struct{})
	sinks := []*fakeSink{sink, newFakeSink()}
	go func() { // 狂调两个导出缝（模拟嵌入方运行中换模块表/换 sink）
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			r.SetModuleFunc("icp", func(context.Context, string, string, []string) error {
				return nil
			})
			r.SetSink(sinks[i%2])
		}
	}()
	for i := 0; i < 5; i++ {
		id := "t-smoke-" + string(rune('a'+i))
		if err := r.Start(id, "icp", "xycovo.com", nil); err != nil {
			t.Fatalf("Start[%d]: %v", i, err)
		}
	}
	deadline := time.Now().Add(8 * time.Second)
	for r.IsRunning("t-smoke-a") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done
	// 并发缝同锁后：无 runtime fatal（并发 map 读写此前直接炸进程）；
	// 终态可能落在被换入的任一 sink 上，两个都数
	terminals := 0
	for _, s := range sinks {
		for _, id := range []string{"t-smoke-a", "t-smoke-b", "t-smoke-c", "t-smoke-d", "t-smoke-e"} {
			switch s.statusOf(id) {
			case store.StatusDone, store.StatusFail, store.StatusStopped:
				terminals++
			}
		}
	}
	if terminals == 0 {
		t.Fatal("并发缝烟雾下应有任务落终态")
	}
}
