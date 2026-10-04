package ui

import (
	"os"
	"path/filepath"
	"testing"

	"recon-native/internal/store"
)

// ── settings.json 持久化 ──

func TestSettingsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{PythonPath: `C:\py\python.exe`}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	st, err := LoadSettings(dir)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if st.PythonPath != `C:\py\python.exe` {
		t.Fatalf("回读不符: %+v", st)
	}
	// 文件确实叫 settings.json，且是合法 JSON
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatalf("settings.json 应存在: %v", err)
	}
}

func TestSettingsMissingFileIsZero(t *testing.T) {
	st, err := LoadSettings(t.TempDir())
	if err != nil {
		t.Fatalf("无文件不应报错: %v", err)
	}
	if st.PythonPath != "" {
		t.Fatalf("无文件应得零值: %+v", st)
	}
}

func TestSettingsCorruptFileFallsBackToZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := LoadSettings(dir)
	if err != nil {
		t.Fatalf("坏文件应兜底不报错: %v", err)
	}
	if st.PythonPath != "" {
		t.Fatalf("坏文件应得零值: %+v", st)
	}
}

func TestNewSessionPrefersSavedPython(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{PythonPath: `C:\saved\python.exe`}); err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(t.TempDir(), dir, `C:\env\python.exe`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Runner.ResolvePython()
	if err != nil || got != `C:\saved\python.exe` {
		t.Fatalf("已保存的解释器路径应优先于入参: got=%q err=%v", got, err)
	}
}

func TestSetPythonPathPersists(t *testing.T) {
	s := newTestSession(t)
	if err := s.SetPythonPath(`C:\new\python.exe`); err != nil {
		t.Fatalf("SetPythonPath: %v", err)
	}
	st, err := LoadSettings(s.DataDir)
	if err != nil || st.PythonPath != `C:\new\python.exe` {
		t.Fatalf("切解释器应写回 settings.json: %+v err=%v", st, err)
	}
}

// ── 模块 tab 筛选 ──

func TestFilterTasksByModule(t *testing.T) {
	tasks := []store.Task{
		{ID: "1", Cmd: "api"},
		{ID: "2", Cmd: "paths"},
		{ID: "3", Cmd: "api"},
	}
	all := FilterTasksByModule(tasks, "")
	if len(all) != 3 {
		t.Fatalf("空筛选应返回全部，得 %d", len(all))
	}
	api := FilterTasksByModule(tasks, "api")
	if len(api) != 2 || api[0].ID != "1" || api[1].ID != "3" {
		t.Fatalf("按模块筛选不符: %+v", api)
	}
	if got := FilterTasksByModule(tasks, "nope"); len(got) != 0 {
		t.Fatalf("未知模块应得 0 条，得 %d", len(got))
	}
}

// ── 分页边界 ──

func TestPageBounds(t *testing.T) {
	cases := []struct {
		total, page, size int
		start, end, pages int
	}{
		{0, 1, 50, 0, 0, 0},        // 空表：0 页
		{101, 1, 50, 0, 50, 3},     // 首页
		{101, 3, 50, 100, 101, 3},  // 末页不满
		{101, 99, 50, 100, 101, 3}, // 页码越界钳到末页
		{101, 0, 50, 0, 50, 3},     // 页码下限钳到 1
		{50, 1, 50, 0, 50, 1},      // 恰好一页
	}
	for _, c := range cases {
		start, end, pages := PageBounds(c.total, c.page, c.size)
		if start != c.start || end != c.end || pages != c.pages {
			t.Fatalf("PageBounds(%d,%d,%d) = (%d,%d,%d), 期望 (%d,%d,%d)",
				c.total, c.page, c.size, start, end, pages, c.start, c.end, c.pages)
		}
	}
}
