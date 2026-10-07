// recon-native —— 信息收集工具桌面壳（Gio 纯 Go 自绘，零 CGO、零网页技术栈）。
//
// 形态：纯本地单窗口工具。六页信息架构：仪表盘 / 新建任务 / 结果 / 工具 /
// 设置 / 暴露面。扫描引擎为 engine-go（同仓库 Go 模块，进程内直调，
// 零子进程零 Python），由 internal/engine 的直调执行器编排；白名单闸、
// 任务库两包为桌面自有实现。
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
