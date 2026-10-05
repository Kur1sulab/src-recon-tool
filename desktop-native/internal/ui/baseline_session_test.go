package ui

// baseline_session_test.go — 基线模块的会话层接线：
//   - normalizeTarget baseline 分支 = 域名形态（拒绝协议/端口，同 subdomain/icp）；
//   - CreateTask("target","baseline",args) 走既有校验链入库并起 recon-go 子进程；
//   - Settings.GoEnginePath 持久化 + SetGoEnginePath/SetPythonPath 互不覆盖。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateTaskBaselineDomainShape(t *testing.T) {
	s := newTestSession(t)
	fakeGoExe := filepath.Join(t.TempDir(), "recon-go.exe")
	if err := os.WriteFile(fakeGoExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Runner.SetGoEnginePath(fakeGoExe)

	// 域名形态放行；可选参数只认 --checks
	id, err := s.CreateTask("xycovo.com", "baseline", "--checks secheaders,webfiles")
	if err != nil {
		t.Fatalf("baseline 域名目标应放行: %v", err)
	}
	got, ok := s.Store.Get(id)
	if !ok {
		t.Fatal("任务应入库")
	}
	if got.Target != "xycovo.com" || got.Cmd != "baseline" || got.Args != "--checks secheaders,webfiles" {
		t.Fatalf("入库不符: %+v", got)
	}

	// 拒绝：协议 / 端口（域名形态闸，同 subdomain/icp）/ 目标旗标夹带
	for _, c := range []struct{ target, args string }{
		{"http://xycovo.com", ""},
		{"xycovo.com:443", ""},
		{"xycovo.com/admin", ""},
		{"127.0.0.1:8799", ""},
		{"xycovo.com", "-d evil.com"},
		{"xycovo.com", "--checks -u"},
		{"xycovo.com", "--verify"},
	} {
		if _, err := s.CreateTask(c.target, "baseline", c.args); err == nil {
			t.Fatalf("baseline 目标 %q args %q 应拒绝", c.target, c.args)
		}
	}
}

func TestSetGoEnginePathPersists(t *testing.T) {
	s := newTestSession(t)
	exe := filepath.Join(t.TempDir(), "go-bin", "recon-go.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGoEnginePath(exe); err != nil {
		t.Fatalf("SetGoEnginePath: %v", err)
	}
	// 生效：runner 立即用新路径
	if p, err := s.Runner.ResolveGoEngine(); err != nil || p != exe {
		t.Fatalf("切换后 ResolveGoEngine = %q, %v", p, err)
	}
	// 持久化：重开 session 仍生效
	st, err := LoadSettings(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.GoEnginePath != exe {
		t.Fatalf("settings.json go_engine_path = %q, 期望 %q", st.GoEnginePath, exe)
	}
	s2, err := NewSession(s.RepoRoot, s.DataDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s2.Runner.ResolveGoEngine(); err != nil || p != exe {
		t.Fatalf("重启后 ResolveGoEngine = %q, %v（应从 settings 恢复）", p, err)
	}
	// 空路径拒绝
	if err := s.SetGoEnginePath("  "); err == nil {
		t.Fatal("空路径应拒绝")
	}
}

func TestSetPythonPathPreservesGoEnginePath(t *testing.T) {
	s := newTestSession(t)
	goExe := filepath.Join(t.TempDir(), "recon-go.exe")
	if err := os.WriteFile(goExe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGoEnginePath(goExe); err != nil {
		t.Fatal(err)
	}
	py := `C:\fake\python39.exe`
	if err := s.SetPythonPath(py); err != nil {
		t.Fatalf("SetPythonPath: %v", err)
	}
	// 保存 Python 路径不得抹掉 Go 引擎路径（两个 setter 都必须全字段保存）
	st, err := LoadSettings(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.PythonPath != py || st.GoEnginePath != goExe {
		t.Fatalf("settings 双字段应齐全: %+v", st)
	}
	// 换装的新 runner 两条解析都要带上
	if p, err := s.Runner.ResolvePython(); err != nil || p != py {
		t.Fatalf("ResolvePython = %q, %v", p, err)
	}
	if p, err := s.Runner.ResolveGoEngine(); err != nil || p != goExe {
		t.Fatalf("换装后 ResolveGoEngine 丢失: %q, %v", p, err)
	}
}
