package apiunauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/mockweb"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// TestEndpointsTableSane 表健全性：27 条、路径 / 开头、risk 枚举
// （对齐 test_new_modules.py:104-111 + 计划的 len==27 断言；与 Python 全等在 parity 做）。
func TestEndpointsTableSane(t *testing.T) {
	if len(Endpoints) != 27 {
		t.Fatalf("Endpoints = %d, want 27（api_unauth.py:22-50 全量）", len(Endpoints))
	}
	for _, e := range Endpoints {
		if !strings.HasPrefix(e.Path, "/") {
			t.Errorf("路径 %q 应以 / 开头", e.Path)
		}
		if e.Risk != "高" && e.Risk != "中" && e.Risk != "低" {
			t.Errorf("risk 非法: %q (%s)", e.Risk, e.Path)
		}
	}
	found := false
	for _, e := range Endpoints {
		if e.Name == "Spring Boot Actuator" {
			found = true
		}
	}
	if !found {
		t.Error("缺 Spring Boot Actuator")
	}
}

// TestClassifyGolden 六例黄金，逐条移植 test_new_modules.py:68-102。
func TestClassifyGolden(t *testing.T) {
	if !Classify("/v3/api-docs", 200, `{"openapi":"3.0.1","paths":{}}`, "application/json", 30,
		[]string{`"openapi"`, `"paths"`}).Hit {
		t.Error("swagger hit 应命中")
	}
	if Classify("/v3/api-docs", 200, "<html><body>首页</body></html>", "text/html", 30,
		[]string{`"openapi"`, `"paths"`}).Hit {
		t.Error("HTML 200 不应命中")
	}
	if Classify("/actuator", 404, "", "", 0, []string{`"_links"`}).Hit {
		t.Error("404 不应命中")
	}
	if !Classify("/actuator/heapdump", 200, "JAVA PROFILE 1.0.8\x00\x00", "application/octet-stream", 4114,
		[]string{"java profile"}).Hit {
		t.Error("heapdump 带魔数应命中")
	}
	if Classify("/actuator/heapdump", 200, strings.Repeat("x", 5000), "application/octet-stream", 5000,
		[]string{"java profile"}).Hit {
		t.Error("heapdump 无魔数不应命中")
	}
	if Classify("/api/v1/users", 200, `{"data":{"username":null}}`, "application/json", 40,
		[]string{`"username"`, `"email"`}).Hit {
		t.Error("多特征端点单特征不应命中（need=2）")
	}
	v := Classify("/api/v1/users", 200, `{"data":{"username":"a","email":"a@b.c"}}`, "application/json", 60,
		[]string{`"username"`, `"email"`})
	if !v.Hit {
		t.Error("多特征端点双特征应命中")
	}
	if !strings.HasPrefix(v.Evidence, "body 含 ") {
		t.Errorf("evidence 前缀 = %q", v.Evidence)
	}
}

// TestProbeNoFalsePositives 四陷阱场景零命中（test_probe_integration.py:52-66）。
func TestProbeNoFalsePositives(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	for _, sc := range []string{"soft404", "api404", "waf", "loginredirect", "empty"} {
		_, hits := Probe(srv.URL+"/"+sc, 5_000_000_000, true)
		if len(hits) != 0 {
			t.Errorf("[%s] 应零命中, got %d", sc, len(hits))
		}
	}
}

// TestProbeRealDetectedAndLive 真阳性：必含五端点且全 live（test_probe_integration.py:74-79）。
func TestProbeRealDetectedAndLive(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	rows, hits := Probe(srv.URL+"/real", 5_000_000_000, true)
	got := map[string]bool{}
	for _, h := range hits {
		got[h["path"].(string)] = true
		if b, _ := h["live"].(bool); !b {
			t.Errorf("%v 应 live=true", h["path"])
		}
	}
	for _, need := range []string{"/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/env", "/actuator/heapdump"} {
		if !got[need] {
			t.Errorf("漏报: %s", need)
		}
	}
	// catch-all 过滤行应带 soft404 标记（/metrics 命中 "# help" 无关此站——此处至少行数齐全）
	if len(rows) != 27 {
		t.Fatalf("rows = %d, want 27", len(rows))
	}
}

func TestRunAPIWritesDocAndEvidence(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	out := t.TempDir()
	hits := RunAPI(srv.URL+"/real", out, true)
	if len(hits) == 0 {
		t.Fatal("real 场景应有命中")
	}
	b, err := os.ReadFile(filepath.Join(out, "api_unauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Base            string           `json:"base"`
		Probed          int              `json:"probed"`
		Hits            []map[string]any `json:"hits"`
		LiveHits        int              `json:"live_hits"`
		Soft404Filtered int              `json:"soft404_filtered"`
		All             []map[string]any `json:"all"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Base != srv.URL+"/real" || doc.Probed != 27 || doc.LiveHits != len(hits) {
		t.Fatalf("api_unauth.json 头部: base=%s probed=%d live=%d", doc.Base, doc.Probed, doc.LiveHits)
	}
	// 取证目录：每个 live 命中都应有 evidence_dir 且三件套齐全
	for _, h := range hits {
		dir, _ := h["evidence_dir"].(string)
		if dir == "" {
			t.Fatalf("%v 缺 evidence_dir", h["path"])
		}
		for _, name := range []string{"meta.json", "response.snippet.txt", "repro.md"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("缺 %s: %v", name, err)
			}
		}
		repro, _ := os.ReadFile(filepath.Join(dir, "repro.md"))
		if !strings.Contains(string(repro), "curl -sk -i") || !strings.Contains(string(repro), "脱敏") {
			t.Errorf("repro.md 缺复现命令/脱敏提醒")
		}
		meta, _ := os.ReadFile(filepath.Join(dir, "meta.json"))
		var mm map[string]any
		if err := json.Unmarshal(meta, &mm); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"url", "collected_at", "status", "size", "digest", "ctype", "server", "name", "risk", "evidence", "live", "recheck"} {
			if _, ok := mm[k]; !ok {
				t.Errorf("meta 缺字段 %s", k)
			}
		}
	}
}

// TestSaveEvidencePathSafety host/slug 白名单清洗防穿越。
func TestSaveEvidencePathSafety(t *testing.T) {
	out := t.TempDir()
	row := map[string]any{
		"url": "http://127.0.0.1:1/actuator/env", "name": "X", "risk": "高",
		"evidence": "e", "marker": `"propertysources"`, "path": "/actuator/env",
		"live": true,
		"recheck": netutil.LiveResult{Live: true, Attempts: []netutil.Attempt{
			{Status: 200, Size: 3, Digest: "abc"},
		}},
	}
	ev, err := SaveEvidence(row, out)
	if err != nil {
		t.Fatal(err)
	}
	dir := ev["dir"].(string)
	rel, _ := filepath.Rel(out, dir)
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		t.Fatalf("证据目录越界: %s", dir)
	}
	if !strings.Contains(filepath.ToSlash(rel), "evidence/127.0.0.1_1/actuator_env") {
		t.Fatalf("host/slug 清洗结果不符: %s", rel)
	}
}
