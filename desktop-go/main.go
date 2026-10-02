// recon-desktop —— src-recon-tool 桌面壳（go-webview2）。
//
// 形态：纯工具。Go 起 127.0.0.1 本地服务（六接口 + 内嵌前端），
// WebView2 窗口加载该地址；扫描引擎是既有 Python 流水线，
// 由 internal/engine 以子进程方式管理（python src/recon.py <子命令>）。
//
// 用法：
//
//	recon-desktop.exe            # 桌面壳
//	recon-desktop.exe --dev      # 不起壳，只起本地服务并打印地址（联调/对抗测试用）
//	recon-desktop.exe --port 8123
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"recon-desktop/internal/engine"
	"recon-desktop/internal/server"
	"recon-desktop/internal/store"
)

// 不带 all: 前缀：. 与 _ 开头的目录/文件（.mimosa 等工具内部产物）不进 exe，
// 也就不可能被静态服务读出。
//
//go:embed frontend
var frontendFS embed.FS

func main() {
	dev := flag.Bool("dev", false, "开发模式：不起桌面壳，只起本地服务并打印地址")
	port := flag.Int("port", 0, "本地服务端口（默认随机）")
	flag.Parse()

	if !*dev && !acquireSingleInstance() {
		messageBox("侦察工作台已在运行中，请勿重复打开。")
		return
	}

	dataDir := dataDirPath()
	for _, sub := range []string{"logs", "progress"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "初始化数据目录失败: %v\n", err)
			return
		}
	}
	repoRoot := findRepoRoot()

	st, err := store.Open(filepath.Join(dataDir, "tasks.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开任务库失败: %v\n", err)
		return
	}
	runner := engine.NewRunner(repoRoot, dataDir, os.Getenv("RECON_PYTHON"))
	frontend, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		fmt.Fprintf(os.Stderr, "内嵌前端不可用: %v\n", err)
		return
	}
	handler := server.New(server.Deps{
		Store:    st,
		Runner:   runner,
		RepoRoot: repoRoot,
		DataDir:  dataDir,
		Frontend: frontend,
	})

	// 只绑 127.0.0.1：本工具的数据面不对外网开放
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "本地端口监听失败: %v\n", err)
		return
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	baseURL := "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		runner.StopAll() // 退出顺序：先停服务，再杀扫描进程树，防止留僵尸 python
	}

	if *dev {
		fmt.Printf("DEV_URL=%s\n", baseURL)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		shutdown()
		return
	}

	// ── 桌面壳 ──
	wcfg := loadWindow(dataDir)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  filepath.Join(dataDir, "webview"),
		WindowOptions: webview2.WindowOptions{
			Title:  "侦察工作台 · src-recon-tool",
			Width:  wcfg.W,
			Height: wcfg.H,
			Center: true,
		},
	})
	if w == nil {
		messageBox("WebView2 运行时初始化失败，请安装 Microsoft Edge WebView2 Runtime 后重试。")
		shutdown()
		return
	}

	// A2 拖拽最小尺寸：960x640 物理像素（与 window.json 记忆值下限一致）
	enforceMinSize(w.Window(), 960, 640)

	// 关窗确认：有任务在跑时前端 beforeunload 弹原生确认（壳注入脚本，不改前端文件）
	w.Bind("confirmExit", func() bool {
		return len(st.RunningIDs()) == 0
	})
	w.Init(`window.addEventListener("beforeunload",function(e){` +
		`try{if(window.confirmExit&&window.confirmExit()===false){e.preventDefault();e.returnValue=" ";}}catch(_){}});`)

	// 尺寸记忆：主循环每秒采样一次窗口大小
	done := make(chan struct{})
	curW, curH := wcfg.W, wcfg.H
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				w.Dispatch(func() {
					if width, height, ok := windowSize(w.Window()); ok {
						curW, curH = width, height
					}
				})
			}
		}
	}()

	w.Navigate(baseURL)
	w.Run()
	close(done)
	saveWindow(dataDir, curW, curH)
	w.Destroy()
	shutdown()
}

// findRepoRoot 从 exe 目录与 cwd 向上找 src/recon.py（≤4 层），找不到回 "."。
func findRepoRoot() string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		for i := 0; i < 4; i++ {
			candidates = append(candidates, d)
			d = filepath.Dir(d)
		}
	}
	if d, err := os.Getwd(); err == nil {
		for i := 0; i < 4; i++ {
			candidates = append(candidates, d)
			d = filepath.Dir(d)
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "src", "recon.py")); err == nil {
			return c
		}
	}
	return "."
}
