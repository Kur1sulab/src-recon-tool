package engine

// fix3_test.go — 终修轮回归：
//   1. 引擎层纵深闸：名单外目标 / 畸形 id 在 Start 就地拒绝——不依赖
//      调用方（session.CreateTask）先过闸，堵「未来新调用方直连 Start」
//      的纵深缺口（审计 adv-low-1）
//   2. 取值旗标挂尾在 Go 层收闸（P4：此前漏到 Python 侧 argparse 才失败）

import (
	"os/exec"
	"strings"
	"testing"
)

func TestStartEngineLayerGate(t *testing.T) {
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, `C:\fake\python.exe`) // 假 python：闸的断言不依赖真解释器
	r.Command = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	// 名单外目标：调用方闸被绕过也不能起步
	if err := r.Start("ok1", "icp", "example.com", nil); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("名单外目标应在引擎层拒绝, 得 %v", err)
	}
	// 畸形 id（会拼 progress/log 文件路径）：就地拒绝
	if err := r.Start("../evil", "icp", "xycovo.com", nil); err == nil || !strings.Contains(err.Error(), "任务 ID") {
		t.Fatalf("穿越形 id 应在引擎层拒绝, 得 %v", err)
	}
	if err := r.Start(".hidden", "icp", "xycovo.com", nil); err == nil {
		t.Fatal("点开头 id 应拒绝")
	}
	if err := r.Start(strings.Repeat("a", 100), "icp", "xycovo.com", nil); err == nil {
		t.Fatal("超长 id 应拒绝")
	}
	// 闸内放行：正常 id + 名单内目标可起步
	if err := r.Start("ok-1", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("闸内 id+目标应放行: %v", err)
	}
}

func TestValidateExtraArgsTrailingValue(t *testing.T) {
	if err := ValidateExtraArgs("portscan", []string{"--ports"}); err == nil || !strings.Contains(err.Error(), "缺少取值") {
		t.Fatalf("取值旗标挂尾应在 Go 层拒绝, 得 %v", err)
	}
	if err := ValidateExtraArgs("portscan", []string{"--ports", "80"}); err != nil {
		t.Fatalf("正常取值不应拒绝: %v", err)
	}
	if err := ValidateExtraArgs("portscan", []string{"--ports=80"}); err != nil {
		t.Fatalf("等号取值不受挂尾闸影响: %v", err)
	}
	if err := ValidateExtraArgs("subdomain", []string{"--verify"}); err != nil {
		t.Fatalf("store_true 旗标挂尾不算缺值: %v", err)
	}
}
