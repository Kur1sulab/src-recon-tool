package ui

// final_fix_test.go — 集成终修轮验收（ui 会话层）：
// findRepoRoot 仓库根判据随直调重写收紧——引擎内置后仓库根唯一用途是 out/
// 产物落点，探针不得再以退役中的 python 入口脚本（src/recon.py）存在性为
// 判据（python 树缺席即回退 "."，产物目录随启动 CWD 漂移）；改为 engine-go/
// 目录标记（公开模块根，python 退役后仍在）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindRepoRootProbeEngineGoMarker(t *testing.T) {
	stub := t.TempDir()
	// 负例：只有退役中的 src/recon.py 的目录不再判为仓库根
	if err := os.MkdirAll(filepath.Join(stub, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stub, "src", "recon.py"), []byte("# stub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(stub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	if got := findRepoRoot(); got == stub {
		t.Fatalf("src/recon.py 不应再作为仓库根判据，得 %q", got)
	}
	// 正例：engine-go/ 目录标记在 → 判为仓库根
	if err := os.MkdirAll(filepath.Join(stub, "engine-go"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findRepoRoot(); got != stub {
		t.Fatalf("engine-go/ 标记所在目录应判为仓库根，得 %q", got)
	}
}

// TestSettingsLegacyGhostKeysExcreted 退役幽灵设置键（python_path/
// go_engine_path）：旧 settings.json 读入不报错，重写后排出——幽灵数据不再
// 永驻文件。
func TestSettingsLegacyGhostKeysExcreted(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"python_path":"C:\\py\\python.exe","go_engine_path":"C:\\tools\\recon-go.exe"}`
	if err := writeSettingsFile(dir, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(dir); err != nil {
		t.Fatalf("旧文件应可读: %v", err)
	}
	if err := SaveSettings(dir, Settings{}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ghost := range []string{"python_path", "go_engine_path"} {
		if strings.Contains(string(body), ghost) {
			t.Fatalf("重写后应排出退役幽灵键 %s，得 %s", ghost, body)
		}
	}
}
