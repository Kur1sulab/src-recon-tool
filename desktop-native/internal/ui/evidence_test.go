package ui

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── outDirFor：与 desktop-go server / Python make_outdir 三方同规则 ──

func TestOutDirForMapping(t *testing.T) {
	cases := []struct{ target, want string }{
		{"xycovo.com", "xycovo.com"},
		{"http://127.0.0.1:8799/real", "http_127.0.0.1_8799_real"},
		{"a\"b", "a_b"},
		{"con.txt", "con_.txt"}, // Windows 保留设备名主干补 _
		{"..", "unknown"},       // 穿越嫌疑回 unknown
		{"  .  ", "unknown"},    // 剔首尾点/空格后为空回 unknown
	}
	for _, c := range cases {
		got := outDirFor("R", c.target)
		want := filepath.Join("R", "out", c.want)
		if got != want {
			t.Fatalf("outDirFor(%q) = %q, 期望 %q", c.target, got, want)
		}
	}
}

func TestOutDirForStaysUnderOut(t *testing.T) {
	// 与 desktop-go fix1_test 同款穿越用例：目录必须可建且在 out/ 内
	root := t.TempDir()
	outRoot, _ := filepath.Abs(filepath.Join(root, "out"))
	cases := []string{"..", "../..", "http://127.0.0.1:8799/real?x=1", "http://127.0.0.1:8799/real*|<>", `a"b`}
	for _, target := range cases {
		dir := outDirFor(root, target)
		absDir, err := filepath.Abs(dir)
		if err != nil {
			t.Fatalf("target=%q Abs: %v", target, err)
		}
		if !strings.HasPrefix(absDir, outRoot+string(filepath.Separator)) {
			t.Fatalf("target=%q 产物目录越出 out/: %s", target, absDir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("target=%q 目录创建失败（Windows 非法字符未清洗）: %v", target, err)
		}
	}
}

// ── 现成 evidence zip 条目审计 ──

func buildZip(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		fw, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("x"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEvidenceZipSafe(t *testing.T) {
	dir := t.TempDir()
	write := func(names ...string) string {
		p := filepath.Join(dir, "e.zip")
		if err := os.WriteFile(p, buildZip(t, names...), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if !evidenceZipSafe(write("a/b.txt", "c.txt")) {
		t.Fatal("正常条目应判安全")
	}
	for _, bad := range [][]string{
		{"../evil.txt"},
		{"/abs.txt"},
		{`a\b.txt`},
		{"C:steal.txt"},
		{""},
	} {
		if evidenceZipSafe(write(bad...)) {
			t.Fatalf("条目 %v 应判不安全", bad)
		}
	}
}

// ── 证据包导出 ──

func newExportSession(t *testing.T) *Session {
	t.Helper()
	s := newTestSession(t)
	// 任务指向一个产物目录，并在里面放好产物
	if _, err := s.CreateTask("xycovo.com", "icp", ""); err != nil {
		t.Fatal(err)
	}
	id := s.Store.List()[0].ID
	_ = id
	artDir := filepath.Join(s.RepoRoot, "out", "xycovo.com")
	if err := os.MkdirAll(filepath.Join(artDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		if err := os.WriteFile(filepath.Join(artDir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("report.txt", "r")
	write("sub/data.json", "{}")
	write("nested.zip", "zip") // 压缩包不做内嵌重打包
	old := maxEvidenceFile
	maxEvidenceFile = 10 // 测试收索单文件上限，触发超限跳过
	t.Cleanup(func() { maxEvidenceFile = old })
	write("big.txt", "0123456789ABCDEF") // 16 字节 > 上限 10
	return s
}

func TestExportEvidencePacksArtifacts(t *testing.T) {
	s := newExportSession(t)
	task := s.Store.List()[0]
	path, mode, packed, skipped, err := s.ExportEvidence(task.ID)
	if err != nil {
		t.Fatalf("ExportEvidence: %v", err)
	}
	if mode != "packed" {
		t.Fatalf("应现打聚合包，得 %q", mode)
	}
	if !strings.HasSuffix(filepath.ToSlash(path), "evidence/"+task.ID+".zip") {
		t.Fatalf("导出路径应在 dataDir/evidence/ 下: %q", path)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		t.Fatalf("导出物不是合法 zip: %v", err)
	}
	names := map[string]bool{}
	for _, zf := range zr.File {
		names[zf.Name] = true // zip 规范条目名一律 /（ToSlash），这里顺带验证
	}
	if !names["report.txt"] || !names["sub/data.json"] {
		t.Fatalf("产物应入包: %v", names)
	}
	if names["nested.zip"] {
		t.Fatal("嵌套 zip 不应内嵌重打包")
	}
	if !names["_跳过的大文件.txt"] {
		t.Fatal("跳过清单应随包留痕")
	}
	if packed != 2 || skipped != 2 {
		t.Fatalf("打包/跳过计数不符: packed=%d skipped=%d", packed, skipped)
	}
}

func TestExportEvidenceNoArtifacts(t *testing.T) {
	s := newTestSession(t)
	if _, err := s.CreateTask("xycovo.com", "icp", ""); err != nil {
		t.Fatal(err)
	}
	task := s.Store.List()[0]
	if _, _, _, _, err := s.ExportEvidence(task.ID); err == nil {
		t.Fatal("无产物应报错而不是导出空包")
	}
}

func TestExportEvidenceUnknownTask(t *testing.T) {
	s := newTestSession(t)
	if _, _, _, _, err := s.ExportEvidence("no-such"); err == nil {
		t.Fatal("任务不存在应报错")
	}
}
