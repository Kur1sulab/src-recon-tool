//go:build !windows

package ui

// 非 Windows 无需挂钩：滚轮由 gio 自身平台管线处理（本产品交付 Windows
// 桌面，此桩仅保持 app.go 事件循环跨平台可编译）。

import "gioui.org/io/event"

func handlePlatformEvent(event.Event) {}
