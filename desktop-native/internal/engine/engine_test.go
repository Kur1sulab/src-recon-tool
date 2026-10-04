package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"recon-native/internal/store"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// ── 进度解析（纯函数）──

func TestParseLine(t *testing.T) {
	ev, ok := ParseLine([]byte(`{"ts":123.5,"event":"start","module":"api","detail":"x"}`))
	if !ok {
		t.Fatal("合法行应解析成功")
	}
	if ev.Module != "api" || ev.Event != "start" || ev.Ts != 123.5 || ev.Detail != "x" {
		t.Fatalf("字段不符: %+v", ev)
	}
	if _, ok := ParseLine([]byte(`{"bad json`)); ok {
		t.Fatal("坏 JSON 应跳过")
	}
	if _, ok := ParseLine([]byte(`[1,2,3]`)); ok {
		t.Fatal("非对象行应跳过")
	}
	if _, ok := ParseLine([]byte(``)); ok {
		t.Fatal("空行应跳过")
	}
}

func TestTailerIncremental(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.jsonl")
	tr := NewTailer(p)
	if evs := poll(tr, t); len(evs) != 0 {
		t.Fatalf("文件不存在应得 0 事件, 得 %d", len(evs))
	}
	appendFile(t, p, `{"ts":1,"event":"pipeline_start","module":"pipeline","detail":"api"}`+"\n")
	if evs := poll(tr, t); len(evs) != 1 {
		t.Fatalf("第一次应读到 1 条, 得 %d", len(evs))
	}
	// 半行：只写一半，不应产出事件也不应丢偏移
	appendFile(t, p, `{"ts":2,"event":"start"`)
	if evs := poll(tr, t); len(evs) != 0 {
		t.Fatalf("半行不应产出事件, 得 %d", len(evs))
	}
	appendFile(t, p, `,"module":"api","detail":""}`+"\n")
	evs := poll(tr, t)
	if len(evs) != 1 || evs[0].Event != "start" {
		t.Fatalf("补全后应读到 1 条 start: %+v", evs)
	}
}

func poll(tr *Tailer, t *testing.T) []store.ProgressEvent {
	t.Helper()
	return tr.Poll() // Poll 内部容错：读不到文件返回空，不报错
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestHasPipelineEnd(t *testing.T) {
	no := []store.ProgressEvent{{Event: "start"}, {Event: "done"}}
	if HasPipelineEnd(no) {
		t.Fatal("无 pipeline_end 应返回 false")
	}
	yes := append(no, store.ProgressEvent{Event: "pipeline_end", Detail: "done"})
	if !HasPipelineEnd(yes) {
		t.Fatal("有 pipeline_end 应返回 true")
	}
}

// ── argv 构造（纯函数）──

func TestBuildCmdArgs(t *testing.T) {
	cases := []struct {
		cmd, target string
		extra       []string
		want        []string
	}{
		{"all", "xycovo.com", nil, []string{"all", "-t", "xycovo.com"}},
		{"portscan", "47.100.49.228", []string{"--ports", "1-100"}, []string{"portscan", "-t", "47.100.49.228", "--ports", "1-100"}},
		{"subdomain", "xycovo.com", nil, []string{"subdomain", "-d", "xycovo.com"}},
		{"icp", "xycovo.com", nil, []string{"icp", "-d", "xycovo.com"}},
		{"reverse", "47.100.49.228", nil, []string{"reverse", "-i", "47.100.49.228"}},
		{"api", "http://127.0.0.1:8799/real", nil, []string{"api", "-u", "http://127.0.0.1:8799/real"}},
		{"jsintel", "http://127.0.0.1:8799/real", []string{"--max-files", "5"}, []string{"jsintel", "-u", "http://127.0.0.1:8799/real", "--max-files", "5"}},
	}
	for _, c := range cases {
		got, err := BuildCmdArgs(c.cmd, c.target, c.extra)
		if err != nil {
			t.Fatalf("BuildCmdArgs(%s): %v", c.cmd, err)
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Fatalf("BuildCmdArgs(%s) = %v, 期望 %v", c.cmd, got, c.want)
		}
	}
	if _, err := BuildCmdArgs("poc", "x", nil); err == nil {
		t.Fatal("不在九模块内的子命令应报错")
	}
}

// ── python 解析 ──

func TestResolvePythonPrefersExplicit(t *testing.T) {
	r := NewRunner("", t.TempDir(), `C:\fake\python.exe`)
	got, err := r.ResolvePython()
	if err != nil || got != `C:\fake\python.exe` {
		t.Fatalf("显式路径优先: got=%q err=%v", got, err)
	}
}

func TestResolvePythonEnvOverPath(t *testing.T) {
	t.Setenv("RECON_PYTHON", "")
	r := NewRunner("", t.TempDir(), "")
	r.pythonPath = "" // 确保走 env/PATH
	python, _ := exec.LookPath("python")
	if python == "" {
		t.Skip("PATH 上没有 python")
	}
	t.Setenv("RECON_PYTHON", python)
	got, err := r.ResolvePython()
	if err != nil || got != python {
		t.Fatalf("RECON_PYTHON 应优先于 PATH: got=%q err=%v", got, err)
	}
}

// ── 起停（假进程：本机 cmd，零外网）──

// fakeSink 记录回调，供断言。
type fakeSink struct {
	mu     sync.Mutex
	events map[string][]store.ProgressEvent
	status map[string]string
}

func newFakeSink() *fakeSink {
	return &fakeSink{events: map[string][]store.ProgressEvent{}, status: map[string]string{}}
}

func (f *fakeSink) AppendProgress(id string, evs []store.ProgressEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[id] = append(f.events[id], evs...)
}

func (f *fakeSink) SetStatus(id, status string, exitCode *int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = status
}

func (f *fakeSink) snapshot() ([]store.ProgressEvent, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events["t1"], f.status["t1"]
}

// writeEngineStub 在临时 repoRoot 里放一个假 src/recon.py（引擎存在性检查用）。
func writeEngineStub(t *testing.T, repoRoot string) {
	t.Helper()
	p := filepath.Join(repoRoot, "src", "recon.py")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("# stub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStartStopStubProcess(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		// 睡 5 秒的假 python：ping 本机回环，零外网
		return exec.Command("cmd", "/c", "ping", "-n", "6", "127.0.0.1", "-w", "1000", ">nul")
	}
	sink := newFakeSink()
	r.SetSink(sink)
	if err := r.Start("t1", "portscan", "47.100.49.228", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !r.IsRunning("t1") {
		t.Fatal("启动后应处于运行态")
	}
	// 停止：进程树应很快消失
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := r.Stop("t1"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if !r.IsRunning("t1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop 后进程未退出")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// 等监视 goroutine 收尾并标记 stopped
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, st := sink.snapshot()
		if st == store.StatusStopped {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("应标记 stopped, 实际 %q", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestStartMissingPipelineEndSynthesizesFail(t *testing.T) {
	if !isWindows() {
		t.Skip("假进程用例基于 cmd，仅 Windows")
	}
	dir := t.TempDir()
	writeEngineStub(t, dir)
	r := NewRunner(dir, dir, "")
	r.Command = func(name string, args ...string) *exec.Cmd {
		// 立即成功退出、不写任何进度 → 兜底补 pipeline_end fail
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	sink := newFakeSink()
	r.SetSink(sink)
	if err := r.Start("t1", "api", "http://127.0.0.1:8799/real", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs, st := sink.snapshot()
		if st == store.StatusFail {
			last := evs[len(evs)-1]
			if last.Event != "pipeline_end" || last.Detail != "fail" || last.Module != "pipeline" {
				t.Fatalf("兜底事件不符: %+v", last)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("应兜底为 fail, 实际 %q events=%v", st, evs)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestStartFailsWithoutPython(t *testing.T) {
	r := NewRunner(t.TempDir(), t.TempDir(), "")
	r.LookPath = func(string) (string, error) { return "", syscall.EINVAL }
	if err := r.Start("t1", "all", "xycovo.com", nil); err == nil {
		t.Fatal("python 缺失时 Start 应报错")
	}
	if r.IsRunning("t1") {
		t.Fatal("失败启动不应留下运行态")
	}
}
