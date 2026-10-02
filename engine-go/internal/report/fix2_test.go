package report

// fix2_test.go — 第 2 轮修复回归（report）：
//   1. PackEvidence 不再静默丢证：'..' 子串文件名照收入包（穿越防护按段判定）
//   2. ZipStamp 纳秒+PID：同秒并发打包文件名不碰撞
//   3. report.md 的 ICP 表按域名排序取前 5（map 迭代随机 → 确定性）

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackEvidenceKeepsDotDotSubstringNames(t *testing.T) {
	out := t.TempDir()
	evDir := filepath.Join(out, "evidence")
	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"pwn_..%2F..%2Fwin.ini": "EVIDENCE-1", // 对抗实测被静默丢弃的名字
		"dir_a..b/child.json":   `{"k":1}`,    // 目录名含 '..' 子串
		"normal.json":           `{"ok":true}`,
	}
	for rel, content := range files {
		p := filepath.Join(evDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	old := ZipStamp
	ZipStamp = func() string { return "FIX2-STAMP" } // 测试固定
	t.Cleanup(func() { ZipStamp = old })             // 恢复全局，防污染后续用例
	got := PackEvidence(out, "127.0.0.1")
	if got == "" {
		t.Fatal("PackEvidence 应产出 zip")
	}
	zr, err := zip.OpenReader(got)
	if err != nil {
		t.Fatalf("打开 zip: %v", err)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		// 穿越红线：任何条目不得含 .. 段 / 前导 / / 盘符
		if strings.HasPrefix(f.Name, "/") || len(f.Name) > 1 && f.Name[1] == ':' {
			t.Fatalf("条目不安全: %q", f.Name)
		}
		for _, seg := range strings.Split(f.Name, "/") {
			if seg == ".." {
				t.Fatalf("条目含 .. 段: %q", f.Name)
			}
		}
	}
	for _, want := range []string{"evidence/pwn_..%2F..%2Fwin.ini", "evidence/dir_a..b/child.json", "evidence/normal.json"} {
		if !names[want] {
			t.Fatalf("证据包缺条目 %q（静默丢证复发）: %v", want, names)
		}
	}
	// .part 中间文件不得残留为 zip
	if _, err := os.Stat(got + ".part"); err == nil {
		t.Fatal(".part 中间文件不应残留")
	}
}

func TestZipStampConcurrentUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s := ZipStamp()
		if seen[s] {
			t.Fatalf("ZipStamp 同秒碰撞: %s", s)
		}
		seen[s] = true
	}
}

func TestRenderICPDeterministic(t *testing.T) {
	b := map[string]any{
		"reverse_domains": []string{"x.com"},
		"icp": map[string]any{
			"bbb.com": map[string]any{"filed": true, "icp": "ICP-2", "unit": "乙"},
			"aaa.com": map[string]any{"filed": true, "icp": "ICP-1", "unit": "甲"},
			"ccc.com": map[string]any{"filed": true, "icp": "ICP-3", "unit": "丙"},
			"ddd.com": map[string]any{"filed": true, "icp": "ICP-4", "unit": "丁"},
			"eee.com": map[string]any{"filed": true, "icp": "ICP-5", "unit": "戊"},
			"fff.com": map[string]any{"filed": true, "icp": "ICP-6", "unit": "己"},
		},
	}
	md1 := RenderMD(b)
	md2 := RenderMD(b)
	if md1 != md2 {
		t.Fatal("RenderMD 两次输出不一致（map 迭代随机漂移）")
	}
	// 只展示前 5 份，且按域名排序：aaa 在列、fff 不在列
	if !strings.Contains(md1, "ICP（aaa.com）") {
		t.Fatal("应含排序首位 aaa.com")
	}
	if strings.Contains(md1, "ICP（fff.com）") {
		t.Fatal("超过 5 份时应截断，fff.com 不应出现")
	}
	if strings.Contains(md1, "ICP（bbb.com）") && !strings.Contains(md1, "ICP（eee.com）") {
		t.Fatal("排序应确定性：aaa..eee 依次入列")
	}
}
