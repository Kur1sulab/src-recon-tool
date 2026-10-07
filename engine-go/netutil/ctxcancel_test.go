package netutil

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// FetchOpt.Ctx 是全部外联的取消咽喉——已取消的 ctx 必须让请求立即失败
// 返回（不真实拨号、不等满 Timeout）。靶标为本机 httptest 挂死端点，
// 零外网；若咽喉失效，本测试会卡到 30s 超时从而被耗时断言抓住。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hangSrv 挂死端点：客户端不主动断开就永远不返回（请求体读取被上下文终结）。
func hangSrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchCtxCancel(t *testing.T) {
	srv := hangSrv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	res := Fetch(srv.URL, FetchOpt{Timeout: 30 * time.Second, Ctx: ctx})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if res.OK || !strings.Contains(res.Err, "cancel") {
		t.Fatalf("应失败且 error 含 cancel，得到 ok=%v err=%q", res.OK, res.Err)
	}
}

// TestBaselineCtxCancel：软 404 基线探针同样过咽喉；取消后按 unknown 降级。
func TestBaselineCtxCancel(t *testing.T) {
	srv := hangSrv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	bl := BaselineCtx(ctx, srv.URL, 30*time.Second, nil)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if bl.Kind != "unknown" {
		t.Fatalf("取消后应 unknown，得到 %q", bl.Kind)
	}
}

// TestVerifyLiveCtxCancel：存活复验同样过咽喉；取消后 Live=false。
func TestVerifyLiveCtxCancel(t *testing.T) {
	srv := hangSrv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	lv := VerifyLiveCtx(ctx, srv.URL, 2, 30*time.Second, "x", nil)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if lv.Live {
		t.Fatal("取消后 Live 应 false")
	}
}
