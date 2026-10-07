package asset

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunAssetContext 取消语义——FOFA/Hunter 请求过 FetchOpt.Ctx 咽喉，
// 取消后秒级收敛。靶标为本机 httptest 挂死端点（咽喉失效卡 20s 超时
// 被耗时断言抓住），零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunAssetContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	t.Setenv("FOFA_EMAIL", "t@example.invalid")
	t.Setenv("FOFA_KEY", "test-key")
	oldBase, oldCheck := FofaBase, checkURL
	defer func() { FofaBase, checkURL = oldBase, oldCheck }()
	FofaBase = srv.URL + "?%s"
	checkURL = func(u string) (string, error) { return u, nil } // 放行 127.0.0.1 桩
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	RunAssetContext(ctx, "stub.example.com", t.TempDir())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
}
