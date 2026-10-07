package baseline

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunContext + Options.Ctx——终修轮收紧后的取消契约分两档：
//   - 未起步检查：RunContext 循环头检查点拦截，只发 skipped 事件、不落产物
//    （缺文件 = 未运行，桌面不渲染成失败——此前取消后剩余检查逐个写「已取消」
//     占位产物，桌面按 Error 非空全部红「失败」）；
//   - 已起步在跑检查：runOne 的 select ctx.Done 提前返回「已取消」包络并照实
//     落盘（它确实跑过）。
//
// 两档各自的验收用例在 final_fix_test.go（SkipsUnstarted / CancelMidRun）；
// 本文件保留最基础的「预取消 ctx 秒级收敛」回归。靶标为零网络的包内注入。

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunContextCancel(t *testing.T) {
	out := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := RunContext(ctx, Options{
		Domain: "cancel.test", Out: out,
		Checks:          []string{CheckSecHeaders, CheckWebfiles},
		PerCheckTimeout: time.Minute, TotalBudget: 5 * time.Minute,
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级收敛，实耗 %s", elapsed)
	}
	if err != nil {
		t.Fatalf("检查级取消不上抛（聚合器语义），得到 %v", err)
	}
	// 终修契约：预取消 = 两个检查都未起步 → 零产物（缺文件 = 未运行），
	// 不再落「已取消」占位包络（该包络只属于确实起步过的检查）
	for _, c := range []string{CheckSecHeaders, CheckWebfiles} {
		if _, serr := os.Stat(filepath.Join(out, c+".json")); serr == nil {
			t.Fatalf("未起步检查 %s 不得落「已取消」占位产物（缺文件=未运行）", c)
		}
	}
}
