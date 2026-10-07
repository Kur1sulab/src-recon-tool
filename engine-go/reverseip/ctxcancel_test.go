package reverseip

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunReverseContext 取消语义——hackertarget 请求过 FetchOpt.Ctx 咽喉 +
// 重试循环检查点，取消后秒级收敛（不走 3 次×25s 退避）。靶标为本机
// httptest 挂死端点，零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunReverseContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	oldBase := HackertargetBase
	defer func() { HackertargetBase = oldBase }()
	HackertargetBase = srv.URL + "/?q=%s"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	doms := RunReverseContext(ctx, "127.0.0.1", t.TempDir())
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if doms != nil {
		t.Fatalf("取消后应 nil，得到 %v", doms)
	}
}
