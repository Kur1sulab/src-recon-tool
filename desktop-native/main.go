// recon-native —— 信息收集工具桌面壳（Gio 纯 Go 自绘，零 CGO、零网页技术栈）。
//
// 形态：纯本地单窗口工具。五页信息架构：仪表盘 / 新建任务 / 结果 / 工具 / 设置。
// 扫描引擎是既有 Python 流水线，由 internal/engine 以子进程方式管理
// （python src/recon.py <子命令>）；白名单闸、任务库、进度解析三包
// 与 desktop-go 逐字节等价（仅 import 路径不同）。
package main

import (
	"fmt"
	"os"

	"gioui.org/app"

	"recon-native/internal/ui"
)

func main() {
	go func() {
		if err := ui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "信息收集工具退出：", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}
