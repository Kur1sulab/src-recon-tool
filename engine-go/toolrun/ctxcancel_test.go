package toolrun

// ctxcancel_test.go — 第一步「取消能力注入」验收（D）：
// RunSubfinderContext / RunOneForAllContext 把调用方 ctx 接进既有
// CommandContext——父 ctx 已取消时子进程不得启动/必须被杀树，秒级返回。
// 桩为本机 30s 挂死脚本（.bat ping），零外网；若 ctx 未生效会卡满 30s
// 被耗时断言抓住。

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// hangScript 生成挂死 30s 的本机脚本路径（Windows .bat；CreateProcess 经 cmd 解析）。
func hangScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "hang30s.bat")
	body := "@echo off\r\nping -n 31 127.0.0.1 >nul\r\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func cancelledCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

func TestRunSubfinderContextCancel(t *testing.T) {
	if runtime.GOOS == "windows" { // .bat 桩仅 Windows 验证；其它平台跳过
		ctx, cancel := cancelledCtx()
		defer cancel()
		start := time.Now()
		_, err := RunSubfinderContext(ctx, hangScript(t), "example.com", 600*time.Second)
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
		}
		if err == nil {
			t.Fatal("已取消 ctx 应返回 error")
		}
	}
}

func TestRunOneForAllContextCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "oneforall.py"), []byte("# stub\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("RECON_PYTHON", hangScript(t)) // 挂死“解释器”：ctx 不生效即卡 30s
		out := t.TempDir()
		ctx, cancel := cancelledCtx()
		defer cancel()
		start := time.Now()
		subs := RunOneForAllContext(ctx, home, "example.com", out, 600*time.Second)
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
		}
		if len(subs) != 0 {
			t.Fatalf("取消后应空列表，得到 %v", subs)
		}
	}
}
