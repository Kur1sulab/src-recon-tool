package report

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunReportContext 纯本地打包（Collect/RenderMD/PackEvidence 零外联），
// ctx 为契约占位（与九模块入口签名统一，桌面线直调面一致）；本测试钉住
// 「取消的 ctx 不影响本地落盘完整性」——档案照常产出，秒级返回。

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRunReportContextLocal(t *testing.T) {
	out := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	path := RunReportContext(ctx, out, "stub.example.com")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("本地打包应秒级返回，实耗 %s", elapsed)
	}
	if filepath.Dir(path) != out {
		t.Fatalf("应落在产物目录，得到 %q", path)
	}
}
