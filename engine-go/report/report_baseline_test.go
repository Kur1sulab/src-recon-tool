package report

// report_baseline_test.go — 基线 8 槽位收集 + report.md「域名暴露面基线」章
//（§5.0：缺文件零值不编造，语义不变；新章仅在至少一份基线产物在场时渲染）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBaselineFixture 写一份最小基线包络产物。
func writeBaselineFixture(t *testing.T, out, check string) {
	t.Helper()
	body := `{"check":"` + check + `","target":"demo.test","generated_at":"2026-10-06T12:00:00+08:00",
"conclusion":{"level":"warn","text":"测试结论"},
"risks":[{"level":"warn","title":"风险条目一","detail":"明细"}],
"data":{}}`
	if err := os.WriteFile(filepath.Join(out, check+".json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectBaselineSlots(t *testing.T) {
	out := t.TempDir()
	writeBaselineFixture(t, out, "secheaders")
	writeBaselineFixture(t, out, "geoasn")

	b := Collect(out, "demo.test")
	for _, key := range []string{"secheaders", "webfiles", "mailsec", "archives",
		"sslchain", "dnsrec", "whois", "geoasn"} {
		v, ok := b[key].(map[string]any)
		if !ok {
			t.Errorf("槽位 %s 应为 map（缺文件给空 map 零值）, 得 %T", key, b[key])
			continue
		}
		switch key {
		case "secheaders", "geoasn":
			if v["check"] != key {
				t.Errorf("%s 槽位应读到包络: %v", key, v["check"])
			}
		default:
			if len(v) != 0 {
				t.Errorf("%s 缺文件应零值空 map, 得 %v", key, v)
			}
		}
	}
}

func TestRenderMDBaselineSection(t *testing.T) {
	out := t.TempDir()
	writeBaselineFixture(t, out, "secheaders")
	writeBaselineFixture(t, out, "mailsec")

	b := Collect(out, "demo.test")
	md := RenderMD(b)
	if !strings.Contains(md, "## 9. 域名暴露面基线") {
		t.Errorf("缺基线章:\n%s", md)
	}
	for _, want := range []string{"安全响应头（secheaders）", "邮件安全（mailsec）", "测试结论", "风险条目一"} {
		if !strings.Contains(md, want) {
			t.Errorf("基线章缺 %q", want)
		}
	}
	// 未运行的检查不展示（不编造）
	if strings.Contains(md, "TLS 证书链（sslchain）") {
		t.Error("未运行的检查不应展示")
	}
	// error 包络 → 失败态行
	if err := os.WriteFile(filepath.Join(out, "whois.json"), []byte(
		`{"check":"whois","target":"demo.test","generated_at":"2026-10-06T12:00:00+08:00",
"conclusion":{"level":"fail","text":"WHOIS 源超时/不可达"},"risks":[],"data":{},
"error":"RDAP 与 43 端口均不可达"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	md = RenderMD(Collect(out, "demo.test"))
	if !strings.Contains(md, "WHOIS 注册信息（whois）") || !strings.Contains(md, "执行失败：RDAP 与 43 端口均不可达") {
		t.Errorf("error 包络应渲染失败态:\n%s", md)
	}
}

func TestRenderMDNoBaselineSectionWhenEmpty(t *testing.T) {
	b := Collect(t.TempDir(), "demo.test")
	md := RenderMD(b)
	if strings.Contains(md, "域名暴露面基线") {
		t.Error("无基线产物不应渲染基线章")
	}
}
