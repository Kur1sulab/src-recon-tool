package cli

// fix1_cli_test.go — 第 1 轮审计修复回归（engine-go/cli）：
//   1. --progress-file 全局参数契约（审计 medium#4）：事件键序与 recon.py:31-62 对齐，
//      桌面壳 Runner 以此驱动状态机
//   2. MakeOutdir 清洗 + 错误上抛（审计 medium#2 / low#6）
//   3. IsIP 去 TrimSpace（审计 low#9）

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetProgress 恢复包级进度状态（测试串行）。
func resetProgress(t *testing.T) {
	t.Helper()
	old := progressFile
	t.Cleanup(func() { progressFile = old })
}

// readJSONL 读进度文件并按行解析。
func readJSONL(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("进度文件读取失败: %v", err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("非 JSONL 行: %q (%v)", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func TestProgressFileDoneContract(t *testing.T) {
	resetProgress(t)
	dir := t.TempDir()
	t.Chdir(dir)
	pf := filepath.Join(dir, "prog.jsonl")
	// fingerprint 请求失败也 exit 0（RunFingerprint 无错误上抛）→ done 契约
	code := Run([]string{"--progress-file", pf, "fingerprint", "-u", "http://127.0.0.1:1/x"})
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	evs := readJSONL(t, pf)
	var seq []string
	for _, e := range evs {
		// 事件键恰为 {ts,event,module,detail}（desktop store.ProgressEvent 契约）
		if len(e) != 4 {
			t.Fatalf("事件键集漂移: %v", e)
		}
		for _, k := range []string{"ts", "event", "module", "detail"} {
			if _, ok := e[k]; !ok {
				t.Fatalf("缺键 %s: %v", k, e)
			}
		}
		if _, ok := e["ts"].(float64); !ok {
			t.Fatalf("ts 应为数值: %v", e)
		}
		seq = append(seq, e["event"].(string))
	}
	want := []string{"pipeline_start", "start", "done", "pipeline_end"}
	if strings.Join(seq, "|") != strings.Join(want, "|") {
		t.Fatalf("事件序 = %v, want %v", seq, want)
	}
	if evs[0]["module"] != "pipeline" || evs[0]["detail"] != "fingerprint" {
		t.Fatalf("pipeline_start 载荷漂移: %v", evs[0])
	}
	if evs[3]["detail"] != "done" {
		t.Fatalf("pipeline_end detail 应为 done: %v", evs[3])
	}
}

func TestProgressFileFailContract(t *testing.T) {
	resetProgress(t)
	dir := t.TempDir()
	t.Chdir(dir)
	pf := filepath.Join(dir, "prog.jsonl")
	// llm 占位 exit 2 → fail 契约
	if code := Run([]string{"--progress-file=" + pf, "llm", "-d", "x.com"}); code != 2 {
		t.Fatalf("llm 应 exit 2, 得 %d", code)
	}
	evs := readJSONL(t, pf)
	var seq []string
	for _, e := range evs {
		seq = append(seq, e["event"].(string))
	}
	want := []string{"pipeline_start", "start", "fail", "pipeline_end"}
	if strings.Join(seq, "|") != strings.Join(want, "|") {
		t.Fatalf("事件序 = %v, want %v", seq, want)
	}
	if evs[3]["detail"] != "fail" {
		t.Fatalf("pipeline_end detail 应为 fail: %v", evs[3])
	}
}

func TestProgressFileEnvFallbackAndNoEventsOnHelp(t *testing.T) {
	resetProgress(t)
	dir := t.TempDir()
	t.Chdir(dir)
	pf := filepath.Join(dir, "env_prog.jsonl")
	t.Setenv("RECON_PROGRESS_FILE", pf)
	if code := Run([]string{"fingerprint", "-u", "http://127.0.0.1:1/x"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if n := len(readJSONL(t, pf)); n != 4 {
		t.Fatalf("环境变量兜底应生效, 事件数=%d", n)
	}
	// help / 无子命令 / 未知全局参数：不发任何事件（等价 argparse 阶段退出）
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		// fix3（audit low#6）：argparse 无 help 子命令——对齐为未知选择 exit 2
		{"help", []string{"--progress-file", pf, "help"}, 2},
		{"无子命令", []string{"--progress-file", pf}, 1},
		{"未知全局参数", []string{"--wat", "verify"}, 2},
		{"未知子命令", []string{"--progress-file", pf, "nope"}, 2},
	} {
		os.Remove(pf)
		if code := Run(tc.args); code != tc.code {
			t.Fatalf("[%s] exit=%d want %d", tc.name, code, tc.code)
		}
		if _, err := os.Stat(pf); err == nil {
			t.Fatalf("[%s] 不应产生进度事件", tc.name)
		}
	}
	// --progress-file 缺路径 → exit 2
	if code := Run([]string{"--progress-file"}); code != 2 {
		t.Fatalf("缺路径应 exit 2, 得 %d", code)
	}
}

func TestMakeOutdirSanitized(t *testing.T) {
	t.Chdir(t.TempDir())
	outRoot, _ := filepath.Abs("out")
	cases := []struct{ target, wantName string }{
		{"example.com", "example.com"},
		{"http://x.com/a?api_key=TOPSECRET&b=1", "http_x.com_a_api_key_TOPSECRET_b_1"},
		{`..\..\trav`, "_.._trav"}, // 反斜杠换 _ 成单组件（无分隔符即无穿越），首部悬浮点被剥
		{"..", "unknown"},
		{"../..", "_"}, // 单组件 "_"，不构成穿越
		{".", "unknown"},
		{"", "unknown"},
		{"x.com.", "x.com"}, // Windows 剥尾点语义，显式归一
	}
	for _, c := range cases {
		got, err := MakeOutdir(c.target)
		if err != nil {
			t.Fatalf("[%q] MkdirAll: %v", c.target, err)
		}
		abs, _ := filepath.Abs(got)
		if !strings.HasPrefix(abs, outRoot+string(filepath.Separator)) && filepath.Dir(abs) != outRoot {
			t.Fatalf("[%q] 目录越出 out/: %s", c.target, abs)
		}
		base := filepath.Base(got)
		if base != c.wantName {
			t.Fatalf("[%q] 目录名 = %q, want %q", c.target, base, c.wantName)
		}
	}
}

func TestMakeOutdirErrorPropagates(t *testing.T) {
	t.Chdir(t.TempDir())
	// out 占位为普通文件 → MkdirAll(out/<name>) 必败 → 错误上抛（退出码契约对齐）
	if err := os.WriteFile("out", []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MakeOutdir("blocked.example"); err == nil {
		t.Fatal("MkdirAll 失败应上抛错误（对齐 Python os.makedirs 抛 OSError）")
	}
}

func TestIsIPNoTrim(t *testing.T) {
	if IsIP(" 1.2.3.4 ") {
		t.Fatal("带空白输入应判假（对齐 Python ipaddress.ip_address 不去空白）")
	}
	if !IsIP("1.2.3.4") || !IsIP("::1") {
		t.Fatal("合法 IP 应判真")
	}
}
