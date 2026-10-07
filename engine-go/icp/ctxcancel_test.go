package icp

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunICPContext 取消语义——apihz 请求过 FetchOpt.Ctx 咽喉 + 重试循环
// 检查点，取消后秒级收敛（不走 3 次×20s 退避）。靶标为本机 httptest
// 挂死端点，零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunICPContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	t.Setenv("APIHZ_ID", "test-id")
	t.Setenv("APIHZ_KEY", "test-key")
	oldURL := APIHZURL
	defer func() { APIHZURL = oldURL }()
	APIHZURL = srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	RunICPContext(ctx, "stub.example.com", t.TempDir())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
}
