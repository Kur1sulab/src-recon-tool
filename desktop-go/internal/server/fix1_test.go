package server

// fix1_test.go — 第 1 轮审计+对抗修复的回归测试：
//   1. args 目标旗标绕过白名单（high）
//   2. --progress-file 等号形式绕过壳闸
//   3. Host/Origin 校验（DNS rebinding / 跨站盲打）
//   4. 根路径 301 死循环（hStatic）
//   5. outDirFor 清洗（Windows 保留字符 / ".." 越出 out/）
//   6. 崩溃后 running 僵尸任务的 stop 幂等
//   7. 证据包超限文件静默截断
//   8. 已知 API 形状的方法不匹配应 405

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"recon-desktop/internal/store"
)

// doAs 构造带指定 Host/Origin 的请求（模拟伪造 Host / 跨站 Origin）。
func doAs(t *testing.T, h http.Handler, method, path, host, origin, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ── 1. args 目标旗标绕过 ──

func TestArgsCannotOverrideTarget(t *testing.T) {
	h, _, _ := newTestHandler(t)
	cases := []string{
		"-u http://10.0.0.5/injected",
		"--url http://10.0.0.5/injected",
		"-u=http://10.0.0.5/injected",
		"--url=http://10.0.0.5/injected",
		"-U http://10.0.0.5/injected",
		"-t http://10.0.0.5/injected",
		"--target http://10.0.0.5/injected",
		"-t=http://10.0.0.5/injected",
		"-d evil.com",
		"--domain=evil.com",
		"-i 10.0.0.5",
		"--ip=10.0.0.5",
		// argparse 前缀缩写展开（--ur→--url 等 last-wins 覆盖受控目标）
		"-ur http://10.0.0.5/injected",
		"--ur http://10.0.0.5/injected",
		"--u=http://10.0.0.5/injected",
		"--dom evil.com",
		"--ta http://10.0.0.5/injected",
		"--do=evil.com",
		// 白名单旗标夹带目标覆盖
		"--ports 80 -u http://10.0.0.5/injected",
		"--workers 4 --tar http://10.0.0.5/injected",
	}
	for _, args := range cases {
		body, _ := json.Marshal(map[string]string{"target": "xycovo.com", "cmd": "api", "args": args})
		rec := postJSON(t, h, "/api/scans", string(body))
		if rec.Code != 400 {
			t.Fatalf("args=%q 应 400 拒绝（不得绕过受控目标）, 得 %d: %s", args, rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["error"] == "" {
			t.Fatalf("拒绝响应应带 error 字段: %s", rec.Body.String())
		}
	}
}

// ── 2. --progress-file 等号形式 ──

func TestProgressFileAssignRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	for _, args := range []string{"--progress-file=C:/Temp/pwn.jsonl", "--progress_file=C:/Temp/pwn.jsonl"} {
		body, _ := json.Marshal(map[string]string{"target": "xycovo.com", "cmd": "portscan", "args": args})
		rec := postJSON(t, h, "/api/scans", string(body))
		if rec.Code != 400 {
			t.Fatalf("args=%q 应 400 拒绝, 得 %d: %s", args, rec.Code, rec.Body.String())
		}
	}
}

// ── 3. Host / Origin 守卫 ──

func TestForgedHostRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	if rec := doAs(t, h, "GET", "/api/env", "evil.com", "", ""); rec.Code != 403 {
		t.Fatalf("伪造 Host 应 403, 得 %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doAs(t, h, "GET", "/api/env", "127.0.0.1:8799", "", ""); rec.Code != 200 {
		t.Fatalf("本机 Host 应 200, 得 %d", rec.Code)
	}
	if rec := doAs(t, h, "GET", "/api/env", "localhost:8799", "", ""); rec.Code != 200 {
		t.Fatalf("localhost Host 应 200, 得 %d", rec.Code)
	}
}

func TestCrossOriginRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	body := `{"target":"xycovo.com","cmd":"icp"}`
	// 跨站页面（no-cors 简单请求会带 Origin）
	if rec := doAs(t, h, "POST", "/api/scans", "127.0.0.1:8799", "http://evil.com", body); rec.Code != 403 {
		t.Fatalf("跨站 Origin 应 403, 得 %d: %s", rec.Code, rec.Body.String())
	}
	// data:/sandbox 页面 Origin 为 null
	if rec := doAs(t, h, "POST", "/api/scans", "127.0.0.1:8799", "null", body); rec.Code != 403 {
		t.Fatalf("Origin null 应 403, 得 %d: %s", rec.Code, rec.Body.String())
	}
	// 同源请求放行
	rec := doAs(t, h, "POST", "/api/scans", "127.0.0.1:8799", "http://127.0.0.1:8799", body)
	if rec.Code != 200 {
		t.Fatalf("同源 Origin 应 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
}

// ── 4. 静态首页（嵌入前端）──

func TestStaticRootServesIndexNoLoop(t *testing.T) {
	h := New(Deps{
		Frontend: fstest.MapFS{
			"index.html":  &fstest.MapFile{Data: []byte("<html>HOME-MARKER</html>")},
			"css/app.css": &fstest.MapFile{Data: []byte("body{}")},
		},
	})
	// 根路径必须 200 出 index.html 字节，不得 301 自指死循环
	rec := do(t, h, "GET", "/", nil)
	if rec.Code != 200 {
		t.Fatalf("GET / 应 200, 得 %d（此前为 301 ./ 死循环）", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("HOME-MARKER")) {
		t.Fatalf("GET / 应返回 index.html 内容: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type 应为 text/html, 得 %s", ct)
	}
	if rec = do(t, h, "GET", "/index.html", nil); rec.Code != 200 ||
		!bytes.Contains(rec.Body.Bytes(), []byte("HOME-MARKER")) {
		t.Fatalf("GET /index.html 应 200 返回字节, 得 %d", rec.Code)
	}
	// 静态资源正常出
	rec = do(t, h, "GET", "/css/app.css", nil)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("body{}")) {
		t.Fatalf("GET /css/app.css 应 200, 得 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("css Content-Type 应为 text/css, 得 %s", ct)
	}
	// SPA hash 路由兜底：未知路径回 index.html
	rec = do(t, h, "GET", "/some/route", nil)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("HOME-MARKER")) {
		t.Fatalf("未知路径应兜底 index.html, 得 %d", rec.Code)
	}
	// 隐藏目录（.mimosa 等）一律 404
	if rec = do(t, h, "GET", "/.mimosa/secret.txt", nil); rec.Code != 404 {
		t.Fatalf("隐藏目录应 404, 得 %d", rec.Code)
	}
}

// ── 5. outDirFor 清洗 ──

func TestOutDirForStaysUnderOut(t *testing.T) {
	root := t.TempDir()
	outRoot, _ := filepath.Abs(filepath.Join(root, "out"))
	cases := []string{
		"..",
		"../..",
		"http://127.0.0.1:8799/real?x=1",
		"http://127.0.0.1:8799/real*|<>",
		`a"b`,
	}
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

// ── 6. 崩溃残留 running 任务的 stop 幂等 ──

func TestStopStaleRunningTask(t *testing.T) {
	h, st, _ := newTestHandler(t)
	if err := st.Create(&store.Task{ID: "stale-1", Target: "xycovo.com", Cmd: "icp",
		Status: store.StatusRunning, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "POST", "/api/scans/stale-1/stop", bytes.NewBufferString("{}"))
	if rec.Code != 200 {
		t.Fatalf("崩溃残留 running 任务 stop 应幂等 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	got, ok := st.Get("stale-1")
	if !ok || got.Status != store.StatusStopped {
		t.Fatalf("stop 后应落 stopped 终态, 得 %s", got.Status)
	}
}

// ── 7. 证据包超限文件 ──

func TestEvidenceSkipsOversizedWithWarning(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)
	old := maxEvidenceFile
	maxEvidenceFile = 1024
	defer func() { maxEvidenceFile = old }()

	rec := postJSON(t, h, "/api/scans", `{"target":"http://127.0.0.1:8799/real","cmd":"api"}`)
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	outDir := filepath.Join(repoRoot, "out", "http_127.0.0.1_8799_real")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "small.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 4096)
	if err := os.WriteFile(filepath.Join(outDir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, h, id)

	rec2 := do(t, h, "GET", "/api/scans/"+id+"/evidence", nil)
	if rec2.Code != 200 {
		t.Fatalf("evidence 应 200, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec2.Body.Bytes()), int64(rec2.Body.Len()))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	names := map[string]bool{}
	warnContent := ""
	for _, f := range zr.File {
		names[f.Name] = true
		if f.Name == "_跳过的大文件.txt" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			warnContent = string(b)
		}
	}
	if !names["small.txt"] {
		t.Fatalf("zip 应含 small.txt: %v", names)
	}
	if names["big.bin"] {
		t.Fatalf("超限文件不得以截断条目混入 zip: %v", names)
	}
	if !strings.Contains(warnContent, "big.bin") {
		t.Fatalf("zip 应含跳过清单并点名 big.bin, 得: %q", warnContent)
	}
}

// ── 8. 方法不匹配 405 ──

func TestMethodNotAllowedOnKnownAPIShape(t *testing.T) {
	h, _, _ := newTestHandler(t)
	cases := [][2]string{
		{"GET", "/api/scans/whatever/stop"},
		{"DELETE", "/api/scans"},
		{"PUT", "/api/env"},
		{"DELETE", "/api/scans/whatever"},
	}
	for _, c := range cases {
		rec := do(t, h, c[0], c[1], nil)
		if rec.Code != 405 {
			t.Fatalf("%s %s 应 405, 得 %d: %s", c[0], c[1], rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Allow") == "" {
			t.Fatalf("%s %s 应带 Allow 头", c[0], c[1])
		}
	}
	if rec := do(t, h, "GET", "/api/unknown", nil); rec.Code != 404 {
		t.Fatalf("未知 API 仍应 404, 得 %d", rec.Code)
	}
}

// ── 9. 现成 evidence zip 条目审计（fix1 P2）──

func TestEvidenceExistingZipAudited(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)
	outDir := filepath.Join(repoRoot, "out", "xycovo.com")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 种一个带穿越条目的恶意 evidence zip
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, name := range []string{"../../pwn_by_zip.txt", "/abs/lead.txt", `C:\evil.txt`, `ok\seg.txt`} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("恶意条目 %q 无法构造: %v", name, err)
		}
		_, _ = w.Write([]byte("PWNED"))
	}
	zw.Close()
	if err := os.WriteFile(filepath.Join(outDir, "evidence-evil.zip"), zbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// 同目录留一个普通产物，让现打分支有内容可打
	if err := os.WriteFile(filepath.Join(outDir, "report.md"), []byte("# ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"icp"}`)
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	waitTerminal(t, h, id)

	rec2 := do(t, h, "GET", "/api/scans/"+id+"/evidence", nil)
	if rec2.Code != 200 {
		t.Fatalf("evidence 应 200（落到现打分支）, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec2.Body.Bytes()), int64(rec2.Body.Len()))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, ":") {
			t.Fatalf("响应 zip 含不安全条目 %q（恶意现成包被原样下发）", f.Name)
		}
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "report.md" {
			found = true
		}
	}
	if !found {
		t.Fatalf("现打 zip 应含 report.md: %v", zr.File)
	}
}
