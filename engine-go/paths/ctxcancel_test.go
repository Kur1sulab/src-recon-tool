package paths

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunPathsContext 取消语义——基线探针 + 19 条字典循环逐条检查点，
// 取消立即收敛返回 ctx.Err()，不落盘。靶标为本机 httptest 挂死端点
// （咽喉失效会卡 19×12s 被耗时断言抓住），零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunPathsContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	alive, err := RunPathsContext(ctx, srv.URL, t.TempDir())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if err == nil {
		t.Fatal("已取消 ctx 应返回 ctx.Err()")
	}
	if alive != nil {
		t.Fatalf("取消后应 nil，得到 %v", alive)
	}
}
