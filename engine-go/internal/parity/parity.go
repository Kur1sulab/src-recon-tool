// Package parity：Python↔Go 双引擎 parity 测试基建。
// 约定（铁律）：
//   - python 不在 PATH 时一律 t.Skip，不阻塞纯 Go 测试；
//   - 运行 Python 侧统一 PYTHONUTF8=1、cwd=仓库根、PYTHONPATH=src；
//   - 两引擎打同一个 Go httptest 靶站（internal/mockweb），严禁各打各的 mock；
//   - 断言只比「解析后结构」与 strip('\r') 后文本——Python 在 Windows 写 CRLF、
//     Go 写 LF，禁比原始字节。
package parity

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// RepoRoot 返回仓库根目录（本文件位于 engine-go/internal/parity，向上 3 级）。
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// RequiresPython：python 不在 PATH 时跳过当前测试（parity 的前置条件）。
func RequiresPython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("python 不在 PATH，跳过 parity 测试（纯 Go 测试不受影响）")
	}
}

// RunPy 在仓库根运行 python -c <code> [args...]，返回合并输出。
func RunPy(t *testing.T, code string, args ...string) string {
	t.Helper()
	RequiresPython(t)
	cmd := exec.Command("python", append([]string{"-c", code}, args...)...)
	cmd.Dir = RepoRoot()
	cmd.Env = append(os.Environ(),
		"PYTHONUTF8=1",
		"PYTHONPATH="+filepath.Join(RepoRoot(), "src"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python 执行失败: %v\n输出:\n%s", err, out)
	}
	return string(out)
}

// PyJSON：RunPy 后把 stdout 按整体 JSON 解析为 map（纯 JSON 输出的场景用）。
func PyJSON(t *testing.T, code string, args ...string) map[string]any {
	t.Helper()
	out := RunPy(t, code, args...)
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		t.Fatalf("python 输出不是 JSON 对象: %v\n输出:\n%s", err, out)
	}
	return m
}

// PyJSONLastLine：python 侧先打日志、最后一行才是 JSON 的场景用。
func PyJSONLastLine(t *testing.T, code string, args ...string) []any {
	t.Helper()
	out := RunPy(t, code, args...)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	var v []any
	if err := json.Unmarshal([]byte(last), &v); err != nil {
		t.Fatalf("python 最后一行不是 JSON 数组: %v\n最后一行: %s", err, last)
	}
	return v
}

// ToMap：把 Go 侧结构体经 JSON 往返成 map，和 Python 侧同构比较。
func ToMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Go 结构序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Go 结构 JSON 往返失败: %v", err)
	}
	return m
}

// StripCR：文本去 \r（Windows CRLF 漂移防护），供文本类断言使用。
func StripCR(s string) string {
	return strings.ReplaceAll(s, "\r", "")
}
