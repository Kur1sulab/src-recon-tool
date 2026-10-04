package server

// fix3_test.go — 第 2 轮审计修复回归（已知线索收口）：
//
//	现打聚合 zip 的 arcname 必须是 zip 规范的正斜杠形态（evidence/example.com/...），
//	与 Python zipfile 产物同构。Windows 下 filepath.Rel 返回反斜杠
//	（evidence\example.com\...），不做 filepath.ToSlash 归一则：
//	  1. 与 Python 引擎产出的 evidence-*.zip 条目形态不一致（parity 破坏）；
//	  2. 会被自家 evidenceZipSafe 判为不安全（反斜杠即嫌疑，server.go 审计规则），
//	     现成包永远被弃用、每次导出都落到重打分支。
//	同一断言覆盖产物清单接口（collectArtifacts 的 name 字段）。

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceFreshZipArcnamesForwardSlash(t *testing.T) {
	h, _, repoRoot := newTestHandler(t)
	rec := postJSON(t, h, "/api/scans", `{"target":"xycovo.com","cmd":"icp"}`)
	if rec.Code != 200 {
		t.Fatalf("创建任务应 200, 得 %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// 嵌套目录产物：模拟引擎 evidence/<目标>/ 的真实层级
	nested := filepath.Join(repoRoot, "out", "xycovo.com", "evidence", "example.com")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "finding.md"), []byte("# ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "out", "xycovo.com", "report.md"), []byte("# r"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitTerminal(t, h, id)

	// ── 产物清单（详情接口）：name 字段同样必须是正斜杠形态 ──
	recDetail := do(t, h, "GET", "/api/scans/"+id, nil)
	var detail map[string]any
	if err := json.Unmarshal(recDetail.Body.Bytes(), &detail); err != nil {
		t.Fatalf("detail 非法 JSON: %v", err)
	}
	arts, _ := detail["artifacts"].([]any)
	artNames := map[string]bool{}
	for _, a := range arts {
		m, _ := a.(map[string]any)
		name, _ := m["name"].(string)
		artNames[name] = true
		if strings.Contains(name, "\\") {
			t.Fatalf("产物清单 name 含反斜杠 %q —— collectArtifacts 未做 ToSlash 归一", name)
		}
	}
	if !artNames[filepath.ToSlash(filepath.Join("evidence", "example.com", "finding.md"))] {
		t.Fatalf("产物清单应含 evidence/example.com/finding.md（正斜杠形态）, 实际: %v", artNames)
	}

	// ── 现打聚合 zip：arcname 全正斜杠，与 Python zipfile 产物形态一致 ──
	rec2 := do(t, h, "GET", "/api/scans/"+id+"/evidence", nil)
	if rec2.Code != 200 {
		t.Fatalf("evidence 应 200, 得 %d: %s", rec2.Code, rec2.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec2.Body.Bytes()), int64(rec2.Body.Len()))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	got := map[string]bool{}
	for _, f := range zr.File {
		got[f.Name] = true
		if strings.Contains(f.Name, "\\") {
			t.Fatalf("zip arcname 含反斜杠 %q —— Windows 下 filepath.Rel 返回值未做 ToSlash 归一，"+
				"与 Python zipfile 产物 evidence/example.com/... 形态不一致", f.Name)
		}
	}
	for _, want := range []string{"evidence/example.com/finding.md", "report.md"} {
		if !got[want] {
			t.Fatalf("zip 应含正斜杠条目 %q, 实际: %v", want, got)
		}
	}
}
