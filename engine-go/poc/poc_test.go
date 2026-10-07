package poc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestMatchGolden 黄金四例，逐条移植 test_poc_engine.py:11-24。
func TestMatchGolden(t *testing.T) {
	if !Match([]Matcher{{Type: "status", Status: []int{200}}}, 200, "", "or") {
		t.Error("status match")
	}
	if Match([]Matcher{{Type: "status", Status: []int{200}}}, 404, "", "or") {
		t.Error("status miss")
	}
	if !Match([]Matcher{{Type: "contains", Words: []string{"admin"}}}, 200, "<title>admin</title>", "or") {
		t.Error("contains match")
	}
	ms := []Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "contains", Words: []string{"login"}},
	}
	if !Match(ms, 200, "please login", "and") {
		t.Error("and 全中应 true")
	}
	if Match(ms, 200, "hello", "and") {
		t.Error("and 缺一应 false")
	}
}

func TestMatchEmptyAndDefaultCondition(t *testing.T) {
	if Match(nil, 200, "", "or") {
		t.Error("matchers 空应 false")
	}
	// condition 缺省 = or：任一命中即 true
	ms := []Matcher{{Type: "status", Status: []int{401}}, {Type: "contains", Words: []string{"nope"}}}
	if !Match(ms, 401, "", "") {
		t.Error("缺省 condition 应为 or")
	}
	if MatchOne(Matcher{Type: "unknown"}, 200, "") {
		t.Error("未知 matcher 类型应 false")
	}
}

// TestRunPOCWithRepoFixture 用已入库 pocs/example-http-detect.yaml 全链路打 httptest。
func TestRunPOCWithRepoFixture(t *testing.T) {
	tplPath := filepath.Join("..", "..", "pocs", "example-http-detect.yaml") // 包公开化后位于 engine-go/poc（2 级到仓库根）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" {
			t.Errorf("模板请求路径 = %s", r.URL.Path)
		}
		if r.Header.Get("User-Agent") != pocUA {
			t.Errorf("UA = %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusUnauthorized) // 命中 status [200,401,403]
	}))
	defer srv.Close()

	if !RunPOC(srv.URL, tplPath) {
		t.Fatal("401 应命中 example-admin-detect")
	}
	// 不存在模板：不 panic，返回 false
	if RunPOC(srv.URL, filepath.Join("..", "..", "pocs", "no-such.yaml")) {
		t.Fatal("缺模板应 false")
	}
}

func TestRunPOCRequestExceptionContinues(t *testing.T) {
	// 目标不可达：status nil → 打异常 continue，不 panic，返回 false
	tpl := "id: t1\ninfo:\n  name: t\n  severity: info\nrequests:\n  - path: /x\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "t.yaml")
	if err := os.WriteFile(p, []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	if RunPOC("http://127.0.0.1:1", p) {
		t.Fatal("全异常应 false")
	}
}
