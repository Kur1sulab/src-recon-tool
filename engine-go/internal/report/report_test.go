package report

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// synthBundle 合成"侦察产出"，字段名对齐 test_report.py:38-83。
func synthBundle(t *testing.T, out, evDir string) {
	t.Helper()
	write := func(name, content string) {
		if _, err := netutil.SafeWrite(out, name, content); err != nil {
			t.Fatal(err)
		}
	}
	write("reverse_domains.txt", "example.com\n")
	write("subdomains.txt", "a.example.com\nb.example.com\n")
	write("subdomains_live.json", jsonx.Compact([]map[string]any{
		{"host": "a.example.com", "ips": []string{"1.2.3.4"}, "alive": true,
			"http": map[string]any{"scheme": "https", "status": 200, "title": "T"}},
		{"host": "b.example.com", "ips": []any{}, "alive": false, "http": map[string]any{}},
	}))
	write("icp_example.com.json", jsonx.Compact(map[string]any{
		"domain": "example.com", "filed": true, "icp": "京ICP备00000000号-1",
		"unit": "示例科技有限公司", "type": "企业", "time": "2026-01-01"}))
	write("fingerprint.json", jsonx.Compact([]map[string]any{{"name": "Swagger UI", "type": "api"}}))
	write("paths.json", jsonx.Compact(map[string]any{
		"base": "https://example.com", "baseline": map[string]any{"kind": "soft404"},
		"alive": []map[string]any{{"path": "/.env", "status": 200, "size": 63, "verified": true}}, "notes": []any{}}))
	write("api_unauth.json", jsonx.Compact(map[string]any{
		"base": "https://example.com", "probed": 27, "live_hits": 1, "soft404_filtered": 3,
		"hits": []map[string]any{{"path": "/actuator/env", "name": "Actuator env（含配置/口令）", "risk": "高",
			"live": true, "evidence_dir": evDir, "evidence": `body 含 "propertysources"`}}}))
	write("jsintel.json", jsonx.Compact(map[string]any{
		"base": "https://example.com", "page_status": 200,
		"scripts":        map[string]any{"external": 3, "inline": 1, "downloaded": 3, "failed": 0},
		"endpoints":      []string{"/api/v1/users"},
		"endpoints_full": []string{"https://example.com/api/v1/users"},
		"sensitive": []map[string]any{{"file": "/js/app.js", "line": 5, "key": "password",
			"value": "Sup3****", "snippet": "var cfg2={password:'Sup3****'"}},
		"domains": map[string]any{"subdomains": []string{"api.example.com"}, "thirdparty": []string{"cdn.third.cn"},
			"internal_ips": []string{"10.0.0.5"}}}))
	write("ports.json", jsonx.Compact(map[string]any{
		"target": "example.com", "ip": "1.2.3.4", "scanned": 100, "open_count": 2,
		"open": []map[string]any{{"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.0"},
			{"port": 443, "service": "", "banner": ""}}}))

	if err := os.MkdirAll(evDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeEV := func(name, content string) {
		if _, err := netutil.SafeWrite(evDir, name, content); err != nil {
			t.Fatal(err)
		}
	}
	writeEV("meta.json", jsonx.Compact(map[string]any{"url": "https://example.com/actuator/env", "live": true}))
	writeEV("response.snippet.txt", `{"spring.datasource.password":"SUPER_SECRET_VALUE"}`)
	writeEV("repro.md", "curl -sk -i 'https://example.com/actuator/env'\n")
}

// TestCollectMissingOutputsDoNotCrash 空目录 collect 不崩（test_report.py:85-91）。
func TestCollectMissingOutputsDoNotCrash(t *testing.T) {
	empty := t.TempDir()
	b := Collect(empty, "nothing.example")
	md := RenderMD(b)
	if !strings.Contains(md, "目标资产档案") || !strings.Contains(md, "待人工跟进") {
		t.Fatal("渲染缺少必需节")
	}
}

// TestReportDoesNotInlineSecrets 敏感值纪律 + 关键内容（test_report.py:93-99）。
func TestReportDoesNotInlineSecrets(t *testing.T) {
	out := t.TempDir()
	evDir := filepath.Join(out, "evidence", "example.com", "actuator_env")
	synthBundle(t, out, evDir)
	path := RunReport(out, "example.com")
	md, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(md)
	if strings.Contains(s, "SUPER_SECRET_VALUE") {
		t.Fatal("report.md 内联了敏感值")
	}
	for _, need := range []string{"/actuator/env", "京ICP备00000000号-1", "存活 ✓"} {
		if !strings.Contains(s, need) {
			t.Errorf("report.md 缺 %q", need)
		}
	}
	// jsintel/ports 节（test_report.py:101-110）
	for _, need := range []string{"JS 线索", "`https://example.com/api/v1/users`", "Sup3****",
		"开放端口", "| 22 | SSH |", "内网 IP 1 个"} {
		if !strings.Contains(s, need) {
			t.Errorf("report.md 缺 %q", need)
		}
	}
}

// TestPoisonedICPNotRendered 限频脏数据不得渲染为备案号（test_report.py:130-140）。
func TestPoisonedICPNotRendered(t *testing.T) {
	out := t.TempDir()
	if _, err := netutil.SafeWrite(out, "reverse_domains.txt", "bad.example\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := netutil.SafeWrite(out, "icp_bad.example.json", jsonx.Compact(map[string]any{
		"domain": "bad.example", "filed": true, "icp": "查询失败",
		"unit": "查询失败", "type": "查询失败", "time": "查询失败"})); err != nil {
		t.Fatal(err)
	}
	md := RenderMD(Collect(out, "poisoned"))
	if strings.Contains(md, "查询失败 · 查询失败") {
		t.Fatal("脏数据被渲染为备案号")
	}
	if !strings.Contains(md, "未查询到有效备案信息") {
		t.Fatal("缺脏数据防御文案")
	}
}

// TestPackEvidenceArcnamesRelative arcname 相对 out/，禁绝对路径与 ..（test_report.py:112-120）。
func TestPackEvidenceArcnamesRelative(t *testing.T) {
	out := t.TempDir()
	evDir := filepath.Join(out, "evidence", "example.com", "actuator_env")
	synthBundle(t, out, evDir)
	zp := PackEvidence(out, "example.com")
	if zp == "" || !strings.HasSuffix(zp, ".zip") {
		t.Fatalf("zip = %q", zp)
	}
	zr, err := zip.OpenReader(zp)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	hasRepro := false
	for _, f := range zr.File {
		n := f.Name
		if strings.Contains(n, "repro.md") {
			hasRepro = true
		}
		if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "\\\\") {
			t.Errorf("绝对路径: %s", n)
		}
		if strings.Contains(n, "..") {
			t.Errorf("疑似穿越: %s", n)
		}
		// 成员内容抽查（对齐计划"arcname 集合与成员内容"断言）
		if strings.HasSuffix(n, "meta.json") {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if !strings.Contains(string(b), "actuator") {
				t.Errorf("成员 %s 内容不符", n)
			}
		}
	}
	if !hasRepro {
		t.Error("zip 缺 repro.md")
	}
}

// TestPackEmptyWhenNoEvidence 无证据 → ""（test_report.py:142-145）。
func TestPackEmptyWhenNoEvidence(t *testing.T) {
	if got := PackEvidence(t.TempDir(), "x"); got != "" {
		t.Fatalf("无证据应返回空串, got %q", got)
	}
}

// TestIdempotentRegeneration 幂等：重复生成同路径、行数不增（test_report.py:122-128）。
func TestIdempotentRegeneration(t *testing.T) {
	out := t.TempDir()
	evDir := filepath.Join(out, "evidence", "example.com", "actuator_env")
	synthBundle(t, out, evDir)
	oldNow := Now
	Now = func() string { return "2026-10-02T00:00:00+08:00" }
	defer func() { Now = oldNow }()
	p1 := RunReport(out, "example.com")
	b1, _ := os.ReadFile(p1)
	p2 := RunReport(out, "example.com")
	b2, _ := os.ReadFile(p2)
	if p1 != p2 {
		t.Fatal("路径应一致")
	}
	if len(b1) != len(b2) {
		t.Fatalf("幂等破坏: %d vs %d", len(b1), len(b2))
	}
	var m map[string]any
	_ = json.Unmarshal(b1, &m) // report.md 是文本——此处只验证非 JSON 也不报错（m 未用）
}

// TestLLMSummaryAlwaysEmpty Go 版 llm_summary 恒空 → 第 8 节不出现。
func TestLLMSummaryAlwaysEmpty(t *testing.T) {
	out := t.TempDir()
	b := Collect(out, "x.example")
	if s, _ := b["llm_summary"].(string); s != "" {
		t.Fatal("llm_summary 应恒空")
	}
	if strings.Contains(RenderMD(b), "## 8. LLM 辅助小结") {
		t.Fatal("第 8 节不应出现")
	}
}
