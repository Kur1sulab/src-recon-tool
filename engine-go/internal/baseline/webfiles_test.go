package baseline

// webfiles_test.go — 网站文件检查（§5.2）：
//   验收 1：mockweb robots/sitemap/security.txt 样例 → Disallow 条目数/loc 列表/
//           Contact 值与样例一致；paths_extra.txt 落盘。
//   验收 2：含 DOCTYPE/ENTITY 的 sitemap 恶意样例被拒（error）。
//   验收 4：og:title/og:image 抽取正确；外链域名归类正确。
//   验收 5：全程只 GET 目标站自身（mockweb httptest，零第三方外联）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/mockweb"
)

const goodSitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://secexample.com/a</loc></url>
<url><loc>https://secexample.com/b</loc></url>
</urlset>`

const evilDTDSitemap = `<?xml version="1.0"?>
<!DOCTYPE urlset [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<urlset><url><loc>&xxe;</loc></url></urlset>`

const evilDoctypeSitemap = `<!DOCTYPE html><urlset><url><loc>http://x/1</loc></url></urlset>`

func TestParseSitemap(t *testing.T) {
	locs, err := parseSitemap(goodSitemap)
	if err != nil {
		t.Fatalf("良性 sitemap 不应报错: %v", err)
	}
	if len(locs) != 2 || locs[0] != "https://secexample.com/a" {
		t.Errorf("loc 列表 = %v", locs)
	}
	// 验收 2：DOCTYPE/ENTITY 拒绝
	for name, evil := range map[string]string{"entity": evilDTDSitemap, "doctype": evilDoctypeSitemap} {
		if _, err := parseSitemap(evil); err == nil {
			t.Errorf("%s 恶意样例应被拒", name)
		} else if !strings.Contains(err.Error(), "DOCTYPE") && !strings.Contains(err.Error(), "ENTITY") {
			t.Errorf("%s 错误应指明拒绝原因: %v", name, err)
		}
	}
	if _, err := parseSitemap("this is not xml <"); err == nil {
		t.Error("非 XML 应报错")
	}
}

func TestParseRobots(t *testing.T) {
	text := "User-agent: *\nDisallow: /admin\nDisallow: /backup\nAllow: /public\n# comment\nDisallow: \n" +
		"Sitemap: https://secexample.com/sitemap.xml\nUser-agent: badbot\nDisallow: /private\n"
	dis, allow, sitemaps := parseRobots(text)
	if len(dis) != 3 || dis[0] != "/admin" || dis[2] != "/private" {
		t.Errorf("Disallow = %v", dis)
	}
	if len(allow) != 1 || allow[0] != "/public" {
		t.Errorf("Allow = %v", allow)
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://secexample.com/sitemap.xml" {
		t.Errorf("Sitemap = %v", sitemaps)
	}
}

func TestParseSecurityTxt(t *testing.T) {
	f := parseSecurityTxt(mockweb.SecSecurityTxt)
	if f["contact"] != "mailto:security@secexample.com" {
		t.Errorf("contact = %q", f["contact"])
	}
	if f["encryption"] != "https://secexample.com/key.asc" || f["policy"] != "https://secexample.com/policy" ||
		f["preferred-languages"] != "zh, en" {
		t.Errorf("字段抽取 = %v", f)
	}
}

const homeHTML = `<!doctype html><html><head><title>首页标题</title>
<meta property="og:title" content="OG 标题">
<meta content="https://cdn.secexample.com/og.png" property="og:image">
</head><body>
<a href="/about">同站</a>
<a href="https://portal.secexample.com/login">子域</a>
<a href="https://third-cdn.example.net/metrics">外部</a>
<a href="javascript:void(0)">脚本</a>
<a href="#top">锚点</a>
</body></html>`

func TestParseHome(t *testing.T) {
	title, og, hrefs := parseHome(homeHTML)
	if title != "首页标题" {
		t.Errorf("title = %q", title)
	}
	if og["og:title"] != "OG 标题" || og["og:image"] != "https://cdn.secexample.com/og.png" {
		t.Errorf("og 抽取（两种属性序）= %v", og)
	}
	if len(hrefs) != 5 {
		t.Errorf("hrefs = %v", hrefs)
	}
}

func TestClassifyHrefs(t *testing.T) {
	_, og, hrefs := parseHome(homeHTML)
	_ = og
	same, subs, external := classifyHrefs(hrefs, "https://secexample.com", "secexample.com")
	if len(same) != 1 || same[0] != "/about" {
		t.Errorf("同站归类 = %v", same)
	}
	if len(subs) != 1 || subs[0] != "portal.secexample.com" {
		t.Errorf("子域候选 = %v", subs)
	}
	if len(external) != 1 || external[0] != "third-cdn.example.net" {
		t.Errorf("外链归类 = %v", external)
	}
	// javascript:/锚点 不进任何分类
	total := len(same) + len(subs) + len(external)
	if total != 3 {
		t.Errorf("javascript/锚点应被跳过: %d", total)
	}
}

// TestWebfilesMockweb 验收 1+4+5：本地靶站集成，全程只打 127.0.0.1。
func TestWebfilesMockweb(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	dir := t.TempDir()
	o := Options{Domain: "secexample.com", URL: srv.URL + "/sec", Out: dir, AllowPrivate: true, Logf: quietLogf}
	res := RunWebfiles(o)
	if res.Error != "" {
		t.Fatalf("靶站集成不应报错: %s", res.Error)
	}

	// robots：Disallow 条目数与样例一致 + paths_extra.txt 落盘
	robots := res.Data["robots"].(map[string]any)
	if robots["disallow_count"] != 2 {
		t.Errorf("Disallow 应 2 条: %v", robots)
	}
	extra, err := os.ReadFile(filepath.Join(dir, "paths_extra.txt"))
	if err != nil {
		t.Fatalf("paths_extra.txt 缺失: %v", err)
	}
	if !strings.Contains(string(extra), "/admin") || !strings.Contains(string(extra), "/backup") {
		t.Errorf("paths_extra.txt 内容 = %q", extra)
	}

	// sitemap：经 robots Sitemap 行两步取得，loc 与样例一致
	sm := res.Data["sitemap"].(map[string]any)
	locs := sm["urls"].([]string)
	if len(locs) != 2 || !strings.HasSuffix(locs[0], "/sec/page1") || !strings.HasSuffix(locs[1], "/sec/page2") {
		t.Errorf("sitemap locs = %v", locs)
	}

	// security.txt：Contact 值一致
	sec := res.Data["security_txt"].(map[string]any)
	fields := sec["fields"].(map[string]string)
	if fields["contact"] != "mailto:security@secexample.com" {
		t.Errorf("security.txt contact = %q", fields["contact"])
	}

	// 首页 og / 域名归类
	home := res.Data["home"].(map[string]any)
	if home["title"] != "Sec Demo" {
		t.Errorf("title = %v", home["title"])
	}
	og := home["og"].(map[string]string)
	if og["og:title"] != "Sec 演示站" || og["og:image"] != "https://cdn.secexample.com/og.png" {
		t.Errorf("og = %v", og)
	}
	dom := res.Data["domains"].(map[string]any)
	subs := dom["subdomain_candidates"].([]string)
	if len(subs) != 1 || subs[0] != "portal.secexample.com" {
		t.Errorf("子域候选 = %v", subs)
	}
	ext := dom["external"].([]string)
	if len(ext) != 1 || ext[0] != "third-cdn.example.net" {
		t.Errorf("外链 = %v", ext)
	}
}
