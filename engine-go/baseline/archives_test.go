package baseline

// archives_test.go — 历史归档检查（§5.4）验收：
//   1. 离线 CDX 文本 fixture 的解析/分类/去重断言。
//   2. 接口超时 → fail（Error 非空）+ 不编造空结果。
//   3. 行数上限生效：超限截断并打 truncated 标记。
//   4. 高危清单与 paths 字典交叉标注（dup/new）。
// 全部离线（cdxFetch 注入桩）。

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// CDX 真实输出为空格分隔（fl=original,timestamp,mimetype,statuscode）。
const cdxFixture = `http://Demo.test/page 20200101 text/html 200
http://demo.test/page#frag 20200201 text/html 200
http://demo.test/backup.zip 20200301 application/zip 200
http://demo.test/db.sql 20200401 - 200
http://demo.test/admin/login 20200501 text/html 200
https://demo.test/robots.txt 20200601 text/plain 200
http://demo.test/config.php.bak 20200701 - 200
`

func TestParseCDXLines(t *testing.T) {
	rows := []cdxRow{}
	for _, ln := range strings.Split(cdxFixture, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		r, ok := parseCDXLine(ln)
		if !ok {
			t.Fatalf("行解析失败: %q", ln)
		}
		rows = append(rows, r)
	}
	if len(rows) != 7 {
		t.Fatalf("应 7 行, 得 %d", len(rows))
	}
	if rows[0].Original != "http://Demo.test/page" || rows[0].Statuscode != "200" {
		t.Errorf("首行 = %+v", rows[0])
	}
}

func TestNormalizeCDXURL(t *testing.T) {
	// host 小写 + 去 fragment（path 大小写保留，报告 §5.4 口径）
	got := normalizeCDXURL("http://Demo.test/page#frag")
	if got != "http://demo.test/page" {
		t.Errorf("normalize = %q", got)
	}
}

func TestCDXDedupAndClassify(t *testing.T) {
	seen := map[string]bool{}
	var uniq []string
	for _, ln := range strings.Split(cdxFixture, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		r, _ := parseCDXLine(ln)
		key := normalizeCDXURL(r.Original)
		if seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, key)
	}
	if len(uniq) != 6 {
		t.Errorf("去重后应 6 条, 得 %d: %v", len(uniq), uniq)
	}
	// 敏感分流：扩展名 + 关键词
	for path, want := range map[string]bool{
		"/backup.zip": true, "/db.sql": true, "/admin/login": true, "/config.php.bak": true,
		"/page": false, "/robots.txt": false,
	} {
		if got := classifyCDXPath(path); got != want {
			t.Errorf("classify(%q) = %v, want %v", path, got, want)
		}
	}
	// 交叉标注：/backup.zip 在 paths.PathsList → dup；/db.sql → new
	if cross := crossPathsDict("/backup.zip"); cross != "dup" {
		t.Errorf("backup.zip 应 dup, 得 %q", cross)
	}
	if cross := crossPathsDict("/db.sql"); cross != "new" {
		t.Errorf("db.sql 应 new, 得 %q", cross)
	}
}

// cdxStub 按 query 分发：showNumPages → 页数；page=N → 对应页文本。
type cdxStub struct {
	pages   map[int]string
	nPages  string
	calls   []string
	failAll bool
}

func (s *cdxStub) fetch(rawURL string, _ time.Duration) (string, error) {
	s.calls = append(s.calls, rawURL)
	if s.failAll {
		return "", errors.New("context deadline exceeded")
	}
	if strings.Contains(rawURL, "showNumPages=true") {
		return s.nPages, nil
	}
	for n, body := range s.pages {
		if strings.Contains(rawURL, fmt.Sprintf("page=%d&", n)) || strings.HasSuffix(rawURL, fmt.Sprintf("page=%d", n)) {
			return body, nil
		}
	}
	return "", nil
}

func TestCDXPaginationAndTruncate(t *testing.T) {
	old := CDXBase
	CDXBase = "http://127.0.0.1:1/cdx" // 不实际出网（stub 拦截）；仅保证 URL 构造真实
	t.Cleanup(func() { CDXBase = old })

	pageOf := func(n int) string {
		var b strings.Builder
		for i := 0; i < 4; i++ {
			fmt.Fprintf(&b, "http://demo.test/p%d-%d,20200101,html,200\n", n, i)
		}
		return b.String()
	}
	stub := &cdxStub{nPages: "3", pages: map[int]string{0: pageOf(0), 1: pageOf(1), 2: pageOf(2)}}
	oldFetch := cdxFetch
	cdxFetch = stub.fetch
	t.Cleanup(func() { cdxFetch = oldFetch })

	rows, truncated, err := fetchCDX("demo.test", 9) // 上限 9 行 → 第 3 页截断
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("超限应 truncated")
	}
	if len(rows) != 9 {
		t.Errorf("应截断到 9 行, 得 %d", len(rows))
	}
	if len(stub.calls) != 4 { // 1 次 showNumPages + 3 页（第 3 页中途截断）
		t.Errorf("分页请求数 = %d: %v", len(stub.calls), stub.calls)
	}
	// 跨页去重
	pageOfDup := func(n int) string { return "http://demo.test/same,20200101,html,200\n" }
	stub2 := &cdxStub{nPages: "2", pages: map[int]string{0: pageOfDup(0), 1: pageOfDup(1)}}
	cdxFetch = stub2.fetch
	rows2, _, err := fetchCDX("demo.test", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 1 {
		t.Errorf("跨页去重应 1 条, 得 %d", len(rows2))
	}
}

func TestArchivesFailNoFabricate(t *testing.T) {
	stub := &cdxStub{failAll: true}
	oldFetch := cdxFetch
	cdxFetch = stub.fetch
	t.Cleanup(func() { cdxFetch = oldFetch })
	res := RunArchives(Options{Domain: "demo.test", Logf: quietLogf})
	if res.Error == "" {
		t.Fatal("CDX 不可达应置 Error（fail 事件）")
	}
	if len(res.Data["high"].([]archivesHigh)) != 0 || res.Data["total"] != 0 {
		t.Errorf("失败不应编造数据: %v", res.Data)
	}
}

func TestArchivesRun(t *testing.T) {
	stub := &cdxStub{nPages: "1", pages: map[int]string{0: cdxFixture}}
	oldFetch := cdxFetch
	cdxFetch = stub.fetch
	t.Cleanup(func() { cdxFetch = oldFetch })

	dir := t.TempDir()
	res := RunArchives(Options{Domain: "demo.test", Out: dir, Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("不应报错: %s", res.Error)
	}
	if res.Data["total"] != 6 {
		t.Errorf("total 应 6（去重后）: %v", res.Data["total"])
	}
	high := res.Data["high"].([]archivesHigh)
	if len(high) != 4 {
		t.Fatalf("高危应 4 条: %v", high)
	}
	// 交叉标注在产物里可见
	crossOK := 0
	for _, h := range high {
		if h.Cross == "dup" || h.Cross == "new" {
			crossOK++
		}
	}
	if crossOK != 4 {
		t.Errorf("4 条高危都应带 dup/new 标注: %v", high)
	}
	if res.Data["truncated"] != false {
		t.Error("未超限不应 truncated")
	}
}
