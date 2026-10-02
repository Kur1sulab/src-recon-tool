package icp

// fix2b_test.go — 第 2 轮修复回归：
//   1. query 参数必须经 url.Values 编码（domain 含 &/# 等不得注入/覆盖其他参数）
//   2. 凭据默认置空：未配置 APIHZ_ID/APIHZ_KEY 时跳过查询（凭据不写源码字面量）

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestBuildAPIHZQueryEncodesDomain(t *testing.T) {
	q := buildAPIHZQuery("cid1", "key1", "a.com&key=evil")
	if got := q.Get("key"); got != "key1" {
		t.Fatalf("key 不得被 domain 内的 & 注入覆盖, 得 %q", got)
	}
	if got := q.Get("domain"); got != "a.com&key=evil" {
		t.Fatalf("domain 应原样成值, 得 %q", got)
	}
}

func TestQueryICPSkipsWithoutCredentials(t *testing.T) {
	// t.Setenv 恢复由框架负责；置空表示未配置（跳过分支不会走到 retrySleep）
	t.Setenv("APIHZ_ID", "")
	t.Setenv("APIHZ_KEY", "")

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"code":200,"icp":"X"}`))
	}))
	defer srv.Close()
	old := APIHZURL
	APIHZURL = srv.URL
	t.Cleanup(func() { APIHZURL = old })

	res := QueryICP("xycovo.com", 1)
	if hits.Load() != 0 {
		t.Fatal("未配置凭据时不得发起任何请求")
	}
	if res["filed"] != false {
		t.Fatalf("应 filed=false, 得 %v", res)
	}
	if msg, _ := res["msg"].(string); msg == "" {
		t.Fatalf("应带跳过原因文案, 得 %v", res)
	}
}
