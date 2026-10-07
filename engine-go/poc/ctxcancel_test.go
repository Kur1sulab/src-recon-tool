package poc

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunPOCContext 取消语义——模板请求循环过 FetchOpt.Ctx 咽喉 + 逐请求
// 检查点，取消后秒级收敛返回 false。靶标为本机 httptest 挂死端点
// （咽喉失效卡 10s 请求超时被耗时断言抓住），零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunPOCContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	tpl := filepath.Join(t.TempDir(), "t.yaml")
	body := "id: cancel-test\ninfo:\n  name: t\n  severity: info\nrequests:\n  - path: /x\n"
	if err := os.WriteFile(tpl, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if hit := RunPOCContext(ctx, srv.URL, tpl); hit {
		t.Fatal("取消后不应命中")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
}
