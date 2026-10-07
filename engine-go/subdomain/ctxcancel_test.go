package subdomain

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunContext/RunVerifyContext 取消语义——多通道循环检查点（OneForAll→
// crt.sh→certspotter→subfinder→写盘）遇取消立即收敛返回 ctx.Err()；
// verify worker 池取消后停发新任务、不再落盘。靶标为本机 httptest 挂死
// 端点（咽喉失效即卡 30s 被耗时断言抓住），零外网。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func hangSrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cancelledCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

func TestRunContextCancel(t *testing.T) {
	withStubs(t, func() {
		srv := hangSrv(t)
		CrtShURL = srv.URL + "/?q=%%25.%s&output=json"
		SubfinderFind = func() string { return "" } // subfinder 通道缺席
		t.Setenv("ONEFORALL_HOME", "")              // OneForAll 缺席 → 降级链进 crt.sh（挂死桩）
		ctx, cancel := cancelledCtx()
		defer cancel()
		start := time.Now()
		subs, err := RunContext(ctx, "stub.example.com", t.TempDir())
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
		}
		if err == nil {
			t.Fatal("已取消 ctx 应返回 ctx.Err()")
		}
		if subs != nil {
			t.Fatalf("取消后应 nil，得到 %v", subs)
		}
	})
}

func TestRunVerifyContextCancel(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "subdomains.txt"), []byte("a.stub.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := cancelledCtx()
	defer cancel()
	start := time.Now()
	rows := RunVerifyContext(ctx, out, 4, true)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if rows != nil {
		t.Fatalf("取消后不落盘不出行，得到 %v", rows)
	}
	if _, err := os.Stat(filepath.Join(out, "subdomains_live.json")); err == nil {
		t.Fatal("取消后不应写 subdomains_live.json")
	}
}
