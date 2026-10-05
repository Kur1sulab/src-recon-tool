package engine

// baseline_engine_test.go — 基线检查执行器接线（桌面线裁决：recon-go.exe
// baseline 作为第二子进程，与 python recon.py 九模块并行共存）。
// 契约出处：engineScope executor 字段 —— 命令行
//
//	<recon-go.exe> --progress-file <dataDir>/progress/<id>.jsonl baseline -d <域名> [--checks c1,c2,...]
//
// --progress-file 全局参数在子命令之前（engine-go cli.go applyProgressFile
// 只认前置形态）；进度事件流与 python 引擎同构，桌面 Tailer/monitor 零改动复用。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"recon-native/internal/store"
)

func TestCmdAllowedBaseline(t *testing.T) {
	if !CmdAllowed("baseline") {
		t.Fatal("baseline 应进入 cmdSet 白名单（第十个可下发子命令）")
	}
}

func TestBuildCmdArgsBaseline(t *testing.T) {
	got, err := BuildCmdArgs("baseline", "xycovo.com", nil)
	if err != nil {
		t.Fatalf("BuildCmdArgs(baseline): %v", err)
	}
	want := []string{"baseline", "-d", "xycovo.com"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("BuildCmdArgs(baseline) = %v, 期望 %v", got, want)
	}
	got, err = BuildCmdArgs("baseline", "xycovo.com", []string{"--checks", "secheaders,webfiles"})
	if err != nil {
		t.Fatalf("BuildCmdArgs(baseline+checks): %v", err)
	}
	want = []string{"baseline", "-d", "xycovo.com", "--checks", "secheaders,webfiles"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("BuildCmdArgs(baseline+checks) = %v, 期望 %v", got, want)
	}
}

func TestValidateExtraArgsBaseline(t *testing.T) {
	// 放行：--checks 是 baseline 唯一附加旗标（取值型）
	if err := ValidateExtraArgs("baseline", []string{"--checks", "secheaders"}); err != nil {
		t.Fatalf("--checks 应放行: %v", err)
	}
	if err := ValidateExtraArgs("baseline", []string{"--checks=secheaders,dnsrec"}); err != nil {
		t.Fatalf("--checks= 应放行: %v", err)
	}
	// 拒绝：取值旗标挂尾 / 缩写 / 跨模块旗标 / 游离值
	for _, extra := range [][]string{
		{"--checks"},
		{"--check", "secheaders"},
		{"--verify"},
		{"-d", "evil.com"},
		{"secheaders"},
		{"--checks", "-d"},
	} {
		if err := ValidateExtraArgs("baseline", extra); err == nil {
			t.Fatalf("extra %v 应拒绝", extra)
		}
	}
}

func TestResolveGoEnginePriority(t *testing.T) {
	t.Setenv("RECON_GO_EXE", "")
	// 1. 显式设置 > 环境 > 探测
	dir := t.TempDir()
	r := NewRunner(dir, dir, "")
	explicit := filepath.Join(dir, "explicit", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(explicit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicit, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.SetGoEnginePath(explicit)
	if p, err := r.ResolveGoEngine(); err != nil || p != explicit {
		t.Fatalf("显式设置应最优先: p=%q err=%v", p, err)
	}

	// 2. 环境变量 > 仓库探测
	r2 := NewRunner(dir, dir, "")
	envExe := filepath.Join(dir, "env", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(envExe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECON_GO_EXE", envExe)
	if p, err := r2.ResolveGoEngine(); err != nil || p != envExe {
		t.Fatalf("RECON_GO_EXE 应生效: p=%q err=%v", p, err)
	}

	// 3. 仓库探测 repoRoot/engine-go/recon-go.exe
	t.Setenv("RECON_GO_EXE", "")
	r3 := NewRunner(dir, dir, "")
	probeExe := filepath.Join(dir, "engine-go", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(probeExe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probeExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, err := r3.ResolveGoEngine(); err != nil || p != probeExe {
		t.Fatalf("仓库探测应命中 engine-go/recon-go.exe: p=%q err=%v", p, err)
	}

	// 4. 环境变量指向不存在的文件 → 落到探测，探测也没有 → 报错
	empty := t.TempDir()
	t.Setenv("RECON_GO_EXE", filepath.Join(empty, "nope.exe"))
	r4 := NewRunner(empty, empty, "")
	if _, err := r4.ResolveGoEngine(); err == nil {
		t.Fatal("Go 引擎缺失应报错（不静默失败）")
	}
}

// TestStartBaselineUsesGoEngine 基线任务走 recon-go.exe 分支：
//   - 不要求 src/recon.py 存在（Python 流水线缺席也能跑基线）；
//   - argv = [recon-go, --progress-file, <p>, baseline, -d, <目标>]，
//     --progress-file 在子命令之前。
func TestStartBaselineUsesGoEngine(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	goExe := filepath.Join(dir, "engine-go", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(goExe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(dir, dir, "")
	var gotName string
	var gotArgs []string
	r.Command = func(name string, args ...string) *exec.Cmd {
		if gotName == "" { // 只捕获主进程；taskkill 兜底不记
			gotName = name
			gotArgs = append([]string(nil), args...)
		}
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	sink := newFakeSink()
	r.SetSink(sink)
	if err := r.Start("t1", "baseline", "xycovo.com", nil); err != nil {
		t.Fatalf("Start(baseline): %v", err)
	}
	if gotName != goExe {
		t.Fatalf("baseline 应以 recon-go.exe 为主进程, 得 %q", gotName)
	}
	want := []string{"--progress-file", filepath.Join(dir, "progress", "t1.jsonl"), "baseline", "-d", "xycovo.com"}
	if strings.Join(gotArgs, "|") != strings.Join(want, "|") {
		t.Fatalf("baseline argv = %v, 期望 %v", gotArgs, want)
	}
	// 假进程立即退出：monitor 收尾（摘进程表与落终态之间有竞态窗口，
	// 在终态上等）。pipeline_end 缺失时兜底 fail——本用例只钉 argv 与
	// 主进程选择，fail/done 都算收尾完成。
	deadline := time.Now().Add(8 * time.Second)
	for {
		_, st := sink.snapshot()
		if st == store.StatusFail || st == store.StatusDone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("假进程收尾应落终态, 得 %q", st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestStartBaselineFailsWithoutGoEngine Go 引擎缺失时 Start 报错且不静默。
func TestStartBaselineFailsWithoutGoEngine(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECON_GO_EXE", "")
	r := NewRunner(dir, dir, "")
	err := r.Start("t-base", "baseline", "xycovo.com", nil)
	if err == nil {
		t.Fatal("Go 引擎缺失时 Start 应报错")
	}
	if !strings.Contains(err.Error(), "recon-go") {
		t.Fatalf("错误应指认 recon-go 引擎缺失, 得 %v", err)
	}
}

// TestStartPythonBranchIgnoresGoEngine 反向回归：python 分支不要求 Go 引擎
// 存在（两引擎并行共存，互不为前置）。
func TestStartPythonBranchIgnoresGoEngine(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir) // src/recon.py 就位
	t.Setenv("RECON_GO_EXE", "")
	r := NewRunner(dir, dir, `C:\fake\python.exe`)
	r.Command = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	r.SetSink(newFakeSink())
	if err := r.Start("t1", "icp", "xycovo.com", nil); err != nil {
		t.Fatalf("python 分支不应要求 Go 引擎: %v", err)
	}
}


func TestProbeGoEngine(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	// 可执行（exit 0）→ found
	dir := t.TempDir()
	goExe := filepath.Join(dir, "engine-go", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(goExe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "-h" {
			return exec.Command("cmd", "/c", "exit", "/b", "0")
		}
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	found, info := r.ProbeGoEngine()
	if !found {
		t.Fatal("recon-go -h 成功退出应判 found")
	}
	_ = info
	// 缺失 → not found
	r2 := NewRunner(t.TempDir(), t.TempDir(), "")
	t.Setenv("RECON_GO_EXE", "")
	if found, _ := r2.ProbeGoEngine(); found {
		t.Fatal("引擎缺失应判 not found")
	}
}
