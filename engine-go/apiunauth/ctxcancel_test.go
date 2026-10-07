package apiunauth

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunAPIContext 取消语义——基线探针/端点循环（27 候选）遇取消立即收敛，
// 返回 ctx.Err() 且不落盘。靶标为本机 httptest 挂死端点（咽喉失效会卡
// 27×12s 被耗时断言抓住），零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunAPIContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	hits, err := RunAPIContext(ctx, srv.URL, t.TempDir(), false)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if err == nil {
		t.Fatal("已取消 ctx 应返回 ctx.Err()")
	}
	if hits != nil {
		t.Fatalf("取消后应 nil，得到 %d 条", len(hits))
	}
}
