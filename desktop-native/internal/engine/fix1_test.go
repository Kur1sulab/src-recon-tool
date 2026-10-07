package engine

// fix1_test.go — 第 1 轮修复回归（直调重写后保留项）：
// 任务自然跑完后 Stop 按幂等语义返回 ErrNotRunning（调用方按成功处理）。
// 原 ResolvePython 商店占位程序回归与 killTree 幂等回归随子进程路径一并退役。

import (
	"context"
	"errors"
	"testing"

	"recon-native/internal/store"
)

func TestStopAfterCompletionIsIdempotent(t *testing.T) {
	r, sink := newTestRunner(t)
	r.SetModuleFunc("icp", func(context.Context, string, string, []string) error { return nil })
	if err := r.Start("t-exit", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if st := waitTerminal(t, sink, "t-exit"); st != store.StatusDone {
		t.Fatalf("应自然落 done，得 %q", st)
	}
	// 任务已收尾出表：Stop 返回可识别的 ErrNotRunning（调用方按幂等成功处理）
	err := r.Stop("t-exit")
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("已收尾任务 Stop 应返回 ErrNotRunning, 得 %v", err)
	}
}
