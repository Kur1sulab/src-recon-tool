package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"recon-desktop/internal/store"
)

// fix2：DELETE /api/scans/{id} 删除语义——running/created 拒删 409；
// 终态任务删除成功（任务记录+progress/log 数据文件）；out/ 产物保留在盘；删后 GET 404。

// storeTask 造一个指定状态的任务（纯状态闸验证，不经引擎）。
func storeTask(t *testing.T, id, target, cmd, status string) *store.Task {
	t.Helper()
	return &store.Task{ID: id, Target: target, Cmd: cmd, Status: status, CreatedAt: 1}
}

func TestDeleteRunningTaskRejected409(t *testing.T) {
	h, st, dataDir := newTestHandler(t)
	// 直接造一个 running 任务（绕开引擎，纯状态闸验证）
	_ = st.Create(storeTask(t, "run1", "xycovo.com", "portscan", "running"))
	logP := filepath.Join(dataDir, "logs", "run1.log")
	_ = os.MkdirAll(filepath.Dir(logP), 0o755)
	_ = os.WriteFile(logP, []byte("x"), 0o644)

	rec := do(t, h, "DELETE", "/api/scans/run1", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("running 任务应拒删 409, 得 %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := st.Get("run1"); !ok {
		t.Fatal("拒删后任务记录不应消失")
	}
	if _, err := os.Stat(logP); err != nil {
		t.Fatal("拒删后日志文件不应被删")
	}
}

func TestDeleteTerminalTaskSucceeds(t *testing.T) {
	h, st, dataDir := newTestHandler(t)
	_ = st.Create(storeTask(t, "done1", "http://127.0.0.1:8799/real", "api", "done"))
	progressP := filepath.Join(dataDir, "progress", "done1.jsonl")
	logP := filepath.Join(dataDir, "logs", "done1.log")
	_ = os.MkdirAll(filepath.Dir(progressP), 0o755)
	_ = os.WriteFile(progressP, []byte(`{"ts":1,"event":"pipeline_end","module":"pipeline","detail":"done"}`+"\n"), 0o644)
	_ = os.WriteFile(logP, []byte("x"), 0o644)

	rec := do(t, h, "DELETE", "/api/scans/done1", nil)
	if rec.Code != 200 {
		t.Fatalf("终态任务应删除成功 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["ok"] != true {
		t.Fatalf("响应应为 {ok:true}: %s", rec.Body.String())
	}
	if _, ok := st.Get("done1"); ok {
		t.Fatal("删除后任务记录应消失")
	}
	if _, err := os.Stat(progressP); !os.IsNotExist(err) {
		t.Fatal("progress 数据文件应被删除")
	}
	if _, err := os.Stat(logP); !os.IsNotExist(err) {
		t.Fatal("log 数据文件应被删除")
	}

	// 删后 GET 404
	if rec2 := do(t, h, "GET", "/api/scans/done1", nil); rec2.Code != 404 {
		t.Fatalf("删后 GET 应 404, 得 %d", rec2.Code)
	}
	// 重复删除 → 404
	if rec3 := do(t, h, "DELETE", "/api/scans/done1", nil); rec3.Code != 404 {
		t.Fatalf("重复删除应 404, 得 %d", rec3.Code)
	}
}

func TestDeleteUnknownTask404(t *testing.T) {
	h, _, _ := newTestHandler(t)
	if rec := do(t, h, "DELETE", "/api/scans/ghost", nil); rec.Code != 404 {
		t.Fatalf("未知任务删除应 404, 得 %d", rec.Code)
	}
}

func TestDeleteKeepsOutArtifacts(t *testing.T) {
	h, st, repoRoot := newTestHandler(t)
	_ = st.Create(storeTask(t, "doneKeep", "xycovo.com", "subdomain", "done"))
	outDir := filepath.Join(repoRoot, "out", "xycovo.com")
	_ = os.MkdirAll(outDir, 0o755)
	artifact := filepath.Join(outDir, "subdomains.txt")
	_ = os.WriteFile(artifact, []byte("a.xycovo.com\n"), 0o644)

	if rec := do(t, h, "DELETE", "/api/scans/doneKeep", nil); rec.Code != 200 {
		t.Fatalf("终态删除应成功, 得 %d", rec.Code)
	}
	if b, err := os.ReadFile(artifact); err != nil || len(b) == 0 {
		t.Fatal("out/ 产物是用户资产，删除任务后必须保留在盘")
	}
}

func TestWhitelistStillEnforcedAfterFix2(t *testing.T) {
	h, _, _ := newTestHandler(t)
	// 局部回归：fix2 改动不得放松白名单闸
	if rec := postJSON(t, h, "/api/scans", `{"target":"example.com","cmd":"api"}`); rec.Code != 403 {
		t.Fatalf("白名单外目标仍应 403, 得 %d", rec.Code)
	}
	if rec := postJSON(t, h, "/api/scans", `{"target":"127.0.0.1:8799","cmd":"api"}`); rec.Code != 200 {
		t.Fatalf("名单内目标仍应通过: %d %s", rec.Code, rec.Body.String())
	}
}
