package paths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/mockweb"
)

// TestPathsNoFalsePositives 四个误报陷阱场景必须零命中（test_probe_integration.py:52-66）。
func TestPathsNoFalsePositives(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	for _, sc := range []string{"soft404", "api404", "waf", "loginredirect", "empty"} {
		alive := RunPaths(srv.URL+"/"+sc, t.TempDir())
		if len(alive) != 0 {
			t.Errorf("[%s] 应零命中, got %d", sc, len(alive))
		}
	}
}

// TestPathsRealDetected 真阳性：real 场景必含 /.env /robots.txt /actuator 且全 verified
// （test_probe_integration.py:81-86）。
func TestPathsRealDetected(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	out := t.TempDir()
	alive := RunPaths(srv.URL+"/real", out)
	got := map[string]bool{}
	for _, a := range alive {
		got[a.Path] = true
		if a.Verified == nil || !*a.Verified {
			t.Errorf("%s 应 verified=true", a.Path)
		}
	}
	for _, need := range []string{"/.env", "/robots.txt", "/actuator"} {
		if !got[need] {
			t.Errorf("漏报: %s", need)
		}
	}
	// paths.json 结构
	b, err := os.ReadFile(filepath.Join(out, "paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Base     string `json:"base"`
		Baseline struct {
			Kind string `json:"kind"`
		} `json:"baseline"`
		Alive []map[string]any `json:"alive"`
		Notes []map[string]any `json:"notes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Base != srv.URL+"/real" || doc.Baseline.Kind != "normal" {
		t.Fatalf("paths.json 头部 = %s / %s", doc.Base, doc.Baseline.Kind)
	}
	// notes：real 站 kind=normal，404 行两侧（Python/Go）都不进任何产出 → 允许为空；
	// 但在有 catch-all 的站（waf/soft404），过滤行必须齐字段——用 soft404 场景补验。
	softOut := t.TempDir()
	RunPaths(srv.URL+"/soft404", softOut)
	sb, err := os.ReadFile(filepath.Join(softOut, "paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var softDoc struct {
		Baseline struct {
			Kind string `json:"kind"`
		} `json:"baseline"`
		Notes []map[string]any `json:"notes"`
	}
	if err := json.Unmarshal(sb, &softDoc); err != nil {
		t.Fatal(err)
	}
	if softDoc.Baseline.Kind != "soft404" || len(softDoc.Notes) == 0 {
		t.Fatalf("soft404 场景: kind=%s notes=%d", softDoc.Baseline.Kind, len(softDoc.Notes))
	}
	for _, k := range []string{"path", "status", "size", "ctype", "final_url", "shrunk", "verdict"} {
		if _, ok := softDoc.Notes[0][k]; !ok {
			t.Errorf("notes 行缺字段 %s", k)
		}
	}
}

func TestPathsListCount(t *testing.T) {
	if len(PathsList) != 19 {
		t.Fatalf("PathsList = %d 条, 源文件 paths.py:20-26 实数 19 条（逐字对照）", len(PathsList))
	}
	for _, p := range PathsList {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("路径 %q 应以 / 开头", p)
		}
	}
}
