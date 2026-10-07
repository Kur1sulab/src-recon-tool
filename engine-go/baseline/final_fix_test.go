package baseline

// final_fix_test.go — 集成终修轮验收：
//  1. 检查实现 panic 兜底（直调重写后检查在宿主进程内跑，任一检查实现
//     panic 不得拖死整个进程/桌面 exe——就地转失败包络，检查级失败不上抛）；
//  2. Stop 后聚合循环 ctx 检查点：未起步检查发 skipped、不落「已取消」占位
//     产物（桌面契约「缺文件 = 未运行」，不把没跑过的检查渲染成红「失败」）；
//     已起步被取消的检查照实落「已取消」包络（诚实记录它确实跑过）。
//
// 靶标全部包内注入桩，零网络零外联。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// swapCheck 临时替换检查注册表项（用后还原，防污染同包后续用例）。
func swapCheck(t *testing.T, name string, fn func(Options) Result) {
	t.Helper()
	orig := checkFuncs[name]
	checkFuncs[name] = fn
	t.Cleanup(func() { checkFuncs[name] = orig })
}

func TestRunOnePanicContained(t *testing.T) {
	swapCheck(t, CheckWebfiles, func(o Options) Result {
		panic("敌意远端数据引爆检查实现")
	})
	out := t.TempDir()
	err := RunContext(context.Background(), Options{
		Domain: "panic.test", Out: out,
		Checks:          []string{CheckWebfiles, CheckSecHeaders},
		PerCheckTimeout: 5 * time.Second, TotalBudget: time.Minute,
	})
	if err != nil {
		t.Fatalf("检查级 panic 不得上抛（聚合器语义），得到 %v", err)
	}
	raw, rerr := os.ReadFile(filepath.Join(out, "webfiles.json"))
	if rerr != nil {
		t.Fatalf("panic 应转失败包络落盘: %v", rerr)
	}
	var got struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("包络 JSON 解析失败: %v", err)
	}
	if !strings.Contains(got.Error, "panic") {
		t.Fatalf("产物 error 应注明 panic 兜底，得到 %q", got.Error)
	}
	// 后续检查照常运行（panic 只死本检查，不中断聚合）
	if _, serr := os.Stat(filepath.Join(out, "secheaders.json")); serr != nil {
		t.Fatalf("panic 后续检查应照常落盘: %v", serr)
	}
}

func TestRunContextCancelSkipsUnstarted(t *testing.T) {
	// 预取消 ctx：两个检查都未起步 → 零产物、零 start/fail 事件、秒级收敛
	out := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []string
	start := time.Now()
	err := RunContext(ctx, Options{
		Domain: "cancel.test", Out: out,
		Checks:          []string{CheckSecHeaders, CheckWebfiles},
		PerCheckTimeout: time.Minute, TotalBudget: 5 * time.Minute,
		Emit: func(event, module, detail string) { events = append(events, event+":"+module) },
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级收敛，实耗 %s", elapsed)
	}
	if err != nil {
		t.Fatalf("取消不上抛（聚合器语义），得到 %v", err)
	}
	for _, c := range []string{CheckSecHeaders, CheckWebfiles} {
		if _, serr := os.Stat(filepath.Join(out, c+".json")); serr == nil {
			t.Fatalf("未起步检查 %s 不得落「已取消」占位产物（缺文件=未运行）", c)
		}
	}
	if len(events) == 0 {
		t.Fatal("未起步检查应发 skipped 事件（与总预算耗尽分支同构）")
	}
	for _, ev := range events {
		if !strings.HasPrefix(ev, "skipped:") {
			t.Fatalf("未起步检查只应发 skipped 事件（不得 start/fail），得到 %q", events)
		}
	}
}

func TestRunContextCancelMidRun(t *testing.T) {
	// 在跑检查挂到取消 → 照实落「已取消」包络；后续检查被检查点拦下 → 零产物
	swapCheck(t, CheckSecHeaders, func(o Options) Result {
		<-o.Ctx.Done() // 挂住直到取消
		return NewResult(CheckSecHeaders, o.Domain, o.URL)
	})
	out := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := RunContext(ctx, Options{
		Domain: "cancel.test", Out: out,
		Checks:          []string{CheckSecHeaders, CheckWebfiles},
		PerCheckTimeout: time.Minute, TotalBudget: 5 * time.Minute,
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("取消后应秒级收敛，实耗 %s", elapsed)
	}
	if err != nil {
		t.Fatalf("取消不上抛，得到 %v", err)
	}
	raw, rerr := os.ReadFile(filepath.Join(out, CheckSecHeaders+".json"))
	if rerr != nil {
		t.Fatalf("在跑检查被取消应照实落「已取消」包络: %v", rerr)
	}
	var got struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("包络 JSON 解析失败: %v", err)
	}
	if !strings.Contains(got.Error, "取消") {
		t.Fatalf("在跑检查产物应为取消包络，得到 error=%q", got.Error)
	}
	if _, serr := os.Stat(filepath.Join(out, CheckWebfiles+".json")); serr == nil {
		t.Fatal("取消后未起步检查不得落占位产物（缺文件=未运行）")
	}
}
