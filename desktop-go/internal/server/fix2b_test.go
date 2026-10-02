package server

// fix2b_test.go — 第 2 轮审计修复回归：
//   1. hStop 对 created 状态任务生效（此前静默吞掉仍返回 200 ok）
//   2. 引擎终态回写不得把已落定的终态改写（monitor 收尾 vs hStop 幂等分支的乱序）

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"recon-desktop/internal/store"
)

func TestStopCreatedTask(t *testing.T) {
	h, st, _ := newTestHandler(t)
	if err := st.Create(&store.Task{ID: "created-1", Target: "xycovo.com", Cmd: "icp",
		Status: store.StatusCreated, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "POST", "/api/scans/created-1/stop", bytes.NewBufferString("{}"))
	if rec.Code != 200 {
		t.Fatalf("created 任务 stop 应 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := st.Get("created-1")
	if got.Status != store.StatusStopped {
		t.Fatalf("created 任务 stop 后应落 stopped（不得静默吞掉）, 得 %q", got.Status)
	}
}

func TestSinkSetStatusDoesNotRegressTerminal(t *testing.T) {
	h, st, _ := newTestHandler(t)
	_ = h
	if err := st.Create(&store.Task{ID: "term-1", Target: "xycovo.com", Cmd: "icp",
		Status: store.StatusStopped, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	// monitor 收尾在 hStop 幂等分支落终态之后才到：不得把 stopped 改写成 fail
	storeSink{st: st}.SetStatus("term-1", store.StatusFail, nil)
	got, _ := st.Get("term-1")
	if got.Status != store.StatusStopped {
		t.Fatalf("终态不得被引擎回写覆盖, 得 %q", got.Status)
	}
	// 非终态仍正常推进：created → running 放行
	if err := st.Create(&store.Task{ID: "term-2", Target: "xycovo.com", Cmd: "icp",
		Status: store.StatusCreated, CreatedAt: 2}); err != nil {
		t.Fatal(err)
	}
	storeSink{st: st}.SetStatus("term-2", store.StatusRunning, nil)
	got2, _ := st.Get("term-2")
	if got2.Status != store.StatusRunning {
		t.Fatalf("非终态推进不得被拦, 得 %q", got2.Status)
	}
}

// 防回归：stop 幂等语义在 running 残留任务上仍成立（第 1 轮行为保持）。
func TestStopRunningResidueStillWorks(t *testing.T) {
	h, st, _ := newTestHandler(t)
	if err := st.Create(&store.Task{ID: "stale-r2", Target: "xycovo.com", Cmd: "icp",
		Status: store.StatusRunning, CreatedAt: 3}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "POST", "/api/scans/stale-r2/stop", bytes.NewBufferString("{}"))
	if rec.Code != 200 {
		t.Fatalf("running 残留任务 stop 应 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["ok"] != true {
		t.Fatalf("应返回 ok:true: %s", rec.Body.String())
	}
}

// ── P3：重打分支不得把产物目录里的任意 *.zip（含被审计弃用的毒 zip 本体）内嵌进新包 ──

func TestEvidenceRepackSkipsNestedZip(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)
	outDir := filepath.Join(repoRoot, "out", "xycovo.com")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 投一个带穿越条目的毒 zip 到产物目录（无 evidence- 前缀，不会走快路径）
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("../../pwned_by_nested.txt")
	_, _ = w.Write([]byte("PWNED"))
	zw.Close()
	poison := filepath.Join(outDir, "evidence-poison.zip")
	if err := os.WriteFile(poison, zbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// 同目录留普通产物，让现打分支有内容
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
		t.Fatalf("evidence 应 200, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec2.Body.Bytes()), int64(rec2.Body.Len()))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	var warn string
	for _, f := range zr.File {
		if f.Name == "evidence-poison.zip" {
			t.Fatal("重打分支不得内嵌产物目录里的 zip（含被弃用的毒 zip 本体）")
		}
		if f.Name == "_跳过的大文件.txt" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			warn = string(b)
		}
	}
	if !strings.Contains(warn, "evidence-poison.zip") {
		t.Fatalf("跳过清单应点名被弃用的 zip, 得: %q", warn)
	}
}
