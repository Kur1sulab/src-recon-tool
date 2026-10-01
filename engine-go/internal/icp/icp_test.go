package icp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ParseICP 黄金四例，逐条移植 test_new_modules.py:40-65。
func TestParseICPGolden(t *testing.T) {
	r := ParseICP(`{"code":200,"td":"1-1","type":"企业","icp":"粤B2-20090059-5",` +
		`"unit":"深圳市腾讯计算机系统有限公司","domain":"qq.com","time":"2026-01-15"}`)
	if r["filed"] != true {
		t.Fatalf("filed = %v", r["filed"])
	}
	if r["icp"] != "粤B2-20090059-5" || r["unit"] != "深圳市腾讯计算机系统有限公司" {
		t.Fatalf("icp/unit = %v/%v", r["icp"], r["unit"])
	}

	r = ParseICP(`{"code":400,"msg":"查询失败或没有备案。"}`)
	if r["filed"] != false || !strings.Contains(r["msg"].(string), "没有备案") {
		t.Fatalf("not filed = %v", r)
	}

	// 回归：apihz 限频返回 code=200 但字段全是「查询失败」，不能当成备案号
	r = ParseICP(`{"code":200,"icp":"查询失败","unit":"查询失败","domain":"查询失败","time":"查询失败"}`)
	if r["filed"] != false || !strings.Contains(r["msg"].(string), "限频") {
		t.Fatalf("ratelimit = %v", r)
	}

	if ParseICP("<html>502</html>")["filed"] != false {
		t.Fatal("非 JSON 应 filed=false")
	}
	if ParseICP(nil)["filed"] != false {
		t.Fatal("nil 应 filed=false")
	}
}

func TestQueryICPRetryThenSuccess(t *testing.T) {
	oldSleep := retrySleep
	retrySleep = func(time.Duration) {}
	t.Cleanup(func() { retrySleep = oldSleep })
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("domain 参数缺失")
		}
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"code":200,"icp":"京ICP备00000000号","unit":"示例公司","type":"企业","domain":"example.com","time":"2026-01-01"}`))
	}))
	defer srv.Close()
	old := APIHZURL
	APIHZURL = srv.URL
	t.Cleanup(func() { APIHZURL = old })
	t.Setenv("APIHZ_ID", "88888888")
	t.Setenv("APIHZ_KEY", "88888888")

	res := QueryICP("example.com", 3)
	if n.Load() != 3 {
		t.Fatalf("重试计数 = %d, want 3", n.Load())
	}
	if res["filed"] != true || res["icp"] != "京ICP备00000000号" {
		t.Fatalf("res = %v", res)
	}
}

func TestRunICPWritesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":400,"msg":"查询失败或没有备案。"}`))
	}))
	defer srv.Close()
	old := APIHZURL
	APIHZURL = srv.URL
	t.Cleanup(func() { APIHZURL = old })
	out := t.TempDir()
	res := RunICP("example.com", out)
	if res["filed"] != false {
		t.Fatalf("res = %v", res)
	}
	b, err := os.ReadFile(filepath.Join(out, "icp_example.com.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["domain"] != "example.com" || m["filed"] != false {
		t.Fatalf("json = %v", m)
	}
}
