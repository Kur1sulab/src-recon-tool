package fingerprint

import (
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// TestRulesInventory 规则清单回归：条数与 RE2 预编译（包初始化即验证语法）。
func TestRulesInventory(t *testing.T) {
	if len(Rules) != 28 {
		t.Fatalf("规则条数 = %d, want 28（fingerprint.py:15-48 全量移植）", len(Rules))
	}
	if len(compiled) != len(Rules) {
		t.Fatalf("预编译数不齐: %d/%d", len(compiled), len(Rules))
	}
	for i, r := range Rules {
		if r.Where != "header" && r.Where != "body" {
			t.Errorf("规则 %d %s where 非法: %q", i, r.Name, r.Where)
		}
	}
}

func buildHay(t *testing.T, url string) (headerHay, bodyHay string) {
	t.Helper()
	r := netutil.Fetch(url, netutil.FetchOpt{Timeout: 5_000_000_000, MaxBytes: 300000, Follow: true})
	if !r.OK || r.Status != 200 {
		t.Fatalf("fetch %s: %v/%d", url, r.OK, r.Status)
	}
	body := strings.ToLower(r.Body)
	var lines []string
	for k, v := range r.Headers {
		lines = append(lines, k+": "+v)
	}
	return strings.ToLower(strings.Join(lines, "\n")), body
}

func names(hits []Hit) string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Name+"("+h.Type+")")
	}
	return strings.Join(out, ",")
}

// TestMatchFpPage 指纹场景：受控显式头（Server: nginx + X-Powered-By: PHP/7.4）
// + ThinkPHP 技术特征 body，命中序列应严格为 [ThinkPHP, Nginx]（规则顺序）。
func TestMatchFpPage(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	hh, bh := buildHay(t, srv.URL+"/fppage/index")
	got := names(MatchHeaders(hh, bh))
	want := "ThinkPHP(framework),Nginx(server)"
	if got != want {
		t.Fatalf("fppage 命中 = %q, want %q", got, want)
	}
}

// TestMatchSwagger /real/swagger-ui.html 应只命中 Swagger UI。
func TestMatchSwagger(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	hh, bh := buildHay(t, srv.URL+"/real/swagger-ui.html")
	got := names(MatchHeaders(hh, bh))
	if got != "Swagger UI(api)" {
		t.Fatalf("swagger 命中 = %q", got)
	}
}

// TestMatchCaseInsensitive haystack 必须 lowercase 后匹配（Python 语义）：
// 大写特征也能命中；同 Name 多规则只记首次。
func TestMatchCaseInsensitiveAndDedup(t *testing.T) {
	body := strings.ToLower("<html>THINK_EXCEPTION ThinkPHP V5.1 /index.php?s=/a</html>")
	header := strings.ToLower("Content-Type: text/html\nX-Powered-By: thinkphp")
	hits := MatchHeaders(header, body)
	if len(hits) != 1 || hits[0].Name != "ThinkPHP" {
		t.Fatalf("同 Name 应只记一次: %v", hits)
	}
}

// TestMatchSoft404NoFalseHit SPA 外壳不应误命中任何规则。
func TestMatchSoft404NoFalseHit(t *testing.T) {
	hits := MatchHeaders("content-type: text/html; charset=utf-8", strings.ToLower(mockweb.SPAShell))
	if len(hits) != 0 {
		t.Fatalf("SPA 外壳误命中: %v", hits)
	}
}

// TestNoNaturalLanguageThinkPHP 回归平移 test_new_modules.py:114-129：
// 正文出现自然语言 "thinkphp" 不得判 ThinkPHP（body 规则只认技术特征）；
// 技术特征（think_exception + 版本号）仍必须命中。
func TestNoNaturalLanguageThinkPHP(t *testing.T) {
	hay := "我在文章里聊了 think 和 php 的关系，也提到过 thinkphp 这个框架名字。"
	for i, r := range Rules {
		if r.Where != "body" {
			continue
		}
		if compiled[i].MatchString(strings.ToLower(hay)) && r.Name == "ThinkPHP" {
			t.Fatalf("自然语言正文误命中 ThinkPHP（规则 %d）", i)
		}
	}
	techHay := "think_exception: 无法加载模块  ThinkPHP 5.1.37"
	hit := false
	for i, r := range Rules {
		if r.Where == "body" && r.Name == "ThinkPHP" && compiled[i].MatchString(strings.ToLower(techHay)) {
			hit = true
		}
	}
	if !hit {
		t.Fatal("技术特征正文应命中 ThinkPHP")
	}
}
