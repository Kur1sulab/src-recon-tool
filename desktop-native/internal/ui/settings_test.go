package ui

import (
	"os"
	"path/filepath"
	"testing"

	"recon-native/internal/store"
)

// ── settings.json 持久化 ──
//
// 终修轮：Settings 的 PythonPath/GoEnginePath 退役幽灵字段已移除（引擎内置、
// 二子进程退役），Settings 为零字段结构体；LoadSettings/SaveSettings 作为
// 持久化纯函数保留（历史文件可读、毒数据兜底不崩——adv2_uipath 的毒
// settings 回归继续覆盖；幽灵键排出验收在 final_fix_test.go）。

func TestSettingsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSettings(dir, Settings{}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if _, err := LoadSettings(dir); err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	// 文件确实叫 settings.json，且是合法 JSON
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatalf("settings.json 应存在: %v", err)
	}
}

func TestSettingsMissingFileIsZero(t *testing.T) {
	if _, err := LoadSettings(t.TempDir()); err != nil {
		t.Fatalf("无文件不应报错: %v", err)
	}
}

func TestSettingsCorruptFileFallsBackToZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(dir); err != nil {
		t.Fatalf("坏文件应兜底不报错: %v", err)
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
