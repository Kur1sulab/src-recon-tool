package cli

// outdirname_test.go — 第一步 C 项验收：OutdirName 纯函数拆出。
// 桌面直调需要「目标 → 产物目录名」的清洗规则（不含 mkdir），
// 维持 Python recon.py make_outdir / engine-go MakeOutdir / desktop
// evidence.go outDirFor 三方同名契约——本测试钉住清洗结果与 MakeOutdir
// 实际落盘目录名严格一致。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutdirName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/a?b=1", "https_example.com_a_b_1"}, // :// / ? = 全清洗
		{"http://1.2.3.4:8080/x", "http_1.2.3.4_8080_x"},         // "://" 整段先于 ":" "/" 命中 → 单个 _
		{"example.com", "example.com"},
		{"", "unknown"},   // 空 → unknown
		{"..", "unknown"}, // 纯穿越锚 → unknown
		{"CON", "CON_"},   // Windows 保留设备名主干补 _
		{`..\..\x`, "_.._x"}, // \ 换 _ 后 Trim 首尾点：不以 .. 开头，不逃逸
	}
	for _, c := range cases {
		got := OutdirName(c.in)
		if got != c.want {
			t.Errorf("OutdirName(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
	// 防逃逸：清洗结果不得以 .. 组件开头
	if s := OutdirName(`..\..\x`); len(s) >= 2 && s[:2] == ".." {
		t.Errorf("OutdirName 结果不得以 .. 开头，得到 %q", s)
	}
}

// TestMakeOutdirUsesOutdirName：MakeOutdir 落盘目录名必须与 OutdirName 一致
// （拆出纯函数不得漂移既有 mkdir 契约）。
func TestMakeOutdirUsesOutdirName(t *testing.T) {
	tmp := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	out, err := MakeOutdir("https://example.com/a?b=1")
	if err != nil {
		t.Fatalf("MakeOutdir 失败: %v", err)
	}
	if base := filepath.Base(out); base != OutdirName("https://example.com/a?b=1") {
		t.Fatalf("MakeOutdir 目录名 %q 与 OutdirName %q 不一致", base, OutdirName("https://example.com/a?b=1"))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("目录应已创建: %v", err)
	}
}
