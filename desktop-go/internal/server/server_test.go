package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"recon-desktop/internal/engine"
	"recon-desktop/internal/store"
)

// newTestHandler 组装一套离线依赖：假 python（cmd /c exit 0 立即退出，零外网）+ 临时目录。
func newTestHandler(t *testing.T) (http.Handler, *store.Store, string) {
	t.Helper()
	repoRoot := t.TempDir()
	dataDir := t.TempDir()
	p := filepath.Join(repoRoot, "src", "recon.py")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("# stub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dataDir, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := engine.NewRunner(repoRoot, dataDir, "cmd") // 假 python；Command 覆盖后不真跑 cmd
	r.Command = func(name string, args ...string) *exec.Cmd {
		return exec.Command("cmd", "/c", "exit", "/b", "0")
	}
	h := New(Deps{
		Store:    st,
		Runner:   r,
		RepoRoot: repoRoot,
		DataDir:  dataDir,
	})
	return h, st, repoRoot
}

func do(t *testing.T, h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Host = "127.0.0.1:8799" // 模拟壳/浏览器的真实本机请求（Host 守卫按此放行）
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, h, "POST", path, bytes.NewBufferString(body))
}

// waitTerminal 轮询到任务进入终态（假进程立即退出，最多等 8 秒）。
func waitTerminal(t *testing.T, h http.Handler, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		rec := do(t, h, "GET", "/api/scans/"+id, nil)
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err == nil {
			if s, _ := m["status"].(string); s == "done" || s == "fail" || s == "stopped" {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务 8 秒内未到终态: %s", rec.Body.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestCreateScanAndDetailFlow(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"http://127.0.0.1:8799/real","cmd":"api"}`)
	if rec.Code != 200 {
		t.Fatalf("创建应 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["status"] != "created" {
		t.Fatalf("status 应为 created: %v", created)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("应返回非空 id")
	}

	detail := waitTerminal(t, h, id)
	if detail["id"] != id || detail["cmd"] != "api" {
		t.Fatalf("detail 字段缺失: %v", detail)
	}
	if detail["exit_code"] == nil {
		t.Fatalf("终态应有 exit_code: %v", detail)
	}
	if _, ok := detail["progress"].([]any); !ok {
		t.Fatalf("progress 应为数组: %v", detail["progress"])
	}
	if _, ok := detail["artifacts"].([]any); !ok {
		t.Fatalf("artifacts 应为数组: %v", detail["artifacts"])
	}
	if _, ok := detail["log_tail"].(string); !ok {
		t.Fatalf("log_tail 应为字符串: %v", detail["log_tail"])
	}
}

func TestCreateScanURLAutoPrefix(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"127.0.0.1:8799","cmd":"api"}`)
	if rec.Code != 200 {
		t.Fatalf("无协议 URL 应自动补 http:// 并通过: %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec2 := do(t, h, "GET", "/api/scans/"+created["id"].(string), nil)
	var d map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &d)
	if d["target"] != "http://127.0.0.1:8799" {
		t.Fatalf("target 应归一为 http://127.0.0.1:8799, 得 %v", d["target"])
	}
}

func TestCreateScanRejected(t *testing.T) {
	h, _, _ := newTestHandler(t)
	cases := []struct {
		name, body string
		code       int
	}{
		{"白名单外域名", `{"target":"example.com","cmd":"api"}`, 403},
		{"白名单外 IP", `{"target":"1.2.3.4","cmd":"portscan"}`, 403},
		{"环回其他端口", `{"target":"http://127.0.0.1:80/","cmd":"api"}`, 403},
		{"未知子命令", `{"target":"xycovo.com","cmd":"poc"}`, 400},
		{"缺目标", `{"cmd":"api"}`, 400},
		{"坏 JSON", `{not json`, 400},
		{"args 注入进度文件", `{"target":"xycovo.com","cmd":"portscan","args":"--progress-file x"}`, 400},
		{"args 非法字符", `{"target":"xycovo.com","cmd":"portscan","args":"--ports 1;rm"}`, 400},
		{"reverse 要 IP", `{"target":"xycovo.com","cmd":"reverse"}`, 400},
		{"subdomain 要域名", `{"target":"http://xycovo.com/","cmd":"subdomain"}`, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postJSON(t, h, "/api/scans", c.body)
			if rec.Code != c.code {
				t.Fatalf("应 %d, 得 %d: %s", c.code, rec.Code, rec.Body.String())
			}
			var m map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["error"] == "" {
				t.Fatalf("错误响应应为 JSON 且带 error 字段: %s", rec.Body.String())
			}
		})
	}
}

func TestCreateScanArgsOK(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"portscan","args":"--ports 1-100 --timeout 0.5"}`)
	if rec.Code != 200 {
		t.Fatalf("合法 args 应通过: %d %s", rec.Code, rec.Body.String())
	}
}

func TestListScans(t *testing.T) {
	h, _, _ := newTestHandler(t)
	postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"portscan","args":"--ports 80"}`)
	rec := do(t, h, "GET", "/api/scans", nil)
	if rec.Code != 200 {
		t.Fatalf("应 200, 得 %d", rec.Code)
	}
	var m struct {
		Scans []map[string]any `json:"scans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Scans) != 1 {
		t.Fatalf("应有 1 个任务: %s", rec.Body.String())
	}
	s := m.Scans[0]
	for _, k := range []string{"id", "target", "cmd", "status", "created_at"} {
		if _, ok := s[k]; !ok {
			t.Fatalf("列表项缺字段 %s: %v", k, s)
		}
	}
}

func TestDetailNotFoundAndStop(t *testing.T) {
	h, _, _ := newTestHandler(t)
	if rec := do(t, h, "GET", "/api/scans/ghost", nil); rec.Code != 404 {
		t.Fatalf("未知 id 应 404, 得 %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/scans/ghost/stop", bytes.NewBufferString("{}")); rec.Code != 404 {
		t.Fatalf("stop 未知 id 应 404, 得 %d", rec.Code)
	}
}

func TestStopTerminalTaskIsIdempotent(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"127.0.0.1:8799","cmd":"api"}`)
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	waitTerminal(t, h, id)
	rec2 := do(t, h, "POST", "/api/scans/"+id+"/stop", bytes.NewBufferString("{}"))
	if rec2.Code != 200 {
		t.Fatalf("终态任务 stop 应幂等 200, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestEvidenceZip(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)

	// 造一个任务 + out/<dir>/ 产物（无 evidence-*.zip → 现打聚合 zip）
	rec := postJSON(t, h, "/api/scans", `{"target":"http://127.0.0.1:8799/real","cmd":"api"}`)
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	outDir := filepath.Join(repoRoot, "out", "http_127.0.0.1_8799_real")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "api_report.md"), []byte("# api 报告"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, h, id)

	rec2 := do(t, h, "GET", "/api/scans/"+id+"/evidence", nil)
	if rec2.Code != 200 {
		t.Fatalf("evidence 应 200, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type 应为 application/zip, 得 %s", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec2.Body.Bytes()), int64(rec2.Body.Len()))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "api_report.md" {
			found = true
		}
	}
	if !found {
		t.Fatalf("聚合 zip 应含 api_report.md, 实际: %v", zr.File)
	}

	// 再造一个带现成 evidence-*.zip 的任务 → 直接回该 zip
	rec3 := postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"portscan"}`)
	var created2 map[string]any
	_ = json.Unmarshal(rec3.Body.Bytes(), &created2)
	id2 := created2["id"].(string)
	outDir2 := filepath.Join(repoRoot, "out", "xycovo.com")
	if err := os.MkdirAll(outDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("evidence/index.html")
	w.Write([]byte("<html>取证</html>"))
	zw.Close()
	if err := os.WriteFile(filepath.Join(outDir2, "evidence-20260719_133336.zip"), zbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, h, id2)
	rec4 := do(t, h, "GET", "/api/scans/"+id2+"/evidence", nil)
	if rec4.Code != 200 || !bytes.Equal(rec4.Body.Bytes(), zbuf.Bytes()) {
		t.Fatalf("应原样返回现成 evidence zip: code=%d", rec4.Code)
	}
}

func TestEvidenceNoArtifactsIs404(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"icp"}`)
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)
	waitTerminal(t, h, id)
	rec2 := do(t, h, "GET", "/api/scans/"+id+"/evidence", nil)
	if rec2.Code != 404 {
		t.Fatalf("无产物应 404, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestEnvEndpoint(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)
	rec := do(t, h, "GET", "/api/env", nil)
	if rec.Code != 200 {
		t.Fatalf("应 200, 得 %d", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	py, _ := m["python"].(map[string]any)
	if py == nil {
		t.Fatalf("缺 python 对象: %s", rec.Body.String())
	}
	for _, k := range []string{"found", "path", "version", "deps_ok"} {
		if _, ok := py[k]; !ok {
			t.Fatalf("python 缺字段 %s: %v", k, py)
		}
	}
	if _, ok := m["out_dir"].(string); !ok {
		t.Fatalf("out_dir 应为字符串: %v", m["out_dir"])
	}
	if _, ok := m["mock_reachable"].(bool); !ok {
		t.Fatalf("mock_reachable 应为布尔: %v", m["mock_reachable"])
	}
	wl, _ := m["whitelist"].([]any)
	if len(wl) != 3 {
		t.Fatalf("whitelist 应 3 项: %v", wl)
	}
	wantOut := filepath.Join(repoRoot, "out")
	if m["out_dir"] != wantOut {
		t.Fatalf("out_dir = %v, 期望 %v", m["out_dir"], wantOut)
	}
}

func TestNoStoreHeader(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := do(t, h, "GET", "/api/env", nil)
	if cc := rec.Header().Get("Cache-Control"); cc == "" || !bytes.Contains([]byte(cc), []byte("no-store")) {
		t.Fatalf("应有 no-store: %q", cc)
	}
}

func TestStaticFallback(t *testing.T) {
	h, _, _ := newTestHandler(t)
	rec := do(t, h, "GET", "/api/unknown", nil)
	if rec.Code != 404 {
		t.Fatalf("未知 API 应 404, 得 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("未知 API 错误应为 JSON, 得 %s: %s", ct, rec.Body.String())
	}
}
