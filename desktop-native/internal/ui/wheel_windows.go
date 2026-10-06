//go:build windows

package ui

// wheel_windows.go —— 滚轮修复的平台管线（转译纯逻辑见 wheel.go）：
// 子类化 gio 窗口过程，WM_MOUSEWHEEL/WM_MOUSEHWHEEL 先经转译再交给原过程，
// 其余消息一律原样放行。HWND 来源：gio 在窗口建立时向应用投递
// app.Win32ViewEvent{HWND}（gioui.org@v0.10.3 app/os_windows.go:120），
// 事件循环 default 分支 handlePlatformEvent 挂钩；窗口销毁时 gio 会再发
// 一次零值 Win32ViewEvent，installWheelFix 以 hwnd==0 与幂等标志双护栏。

import (
	"unsafe"

	"gioui.org/app"
	"gioui.org/io/event"
	"golang.org/x/sys/windows"
)

// GWLP_WNDPROC = -4，作为 uintptr 传参取二补数。
const gwlpWndProc = ^uintptr(3)

var (
	user32                = windows.NewLazySystemDLL("user32.dll")
	procGetWindowLongPtrW = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW   = user32.NewProc("CallWindowProcW")
	procGetMessageTime    = user32.NewProc("GetMessageTime")
	procGetPointerInfo    = user32.NewProc("GetPointerInfo")

	wheelPrevProc    uintptr // 原窗口过程（CallWindowProc 链尾）
	wheelCallback    uintptr // NewCallback 产物必须全程持引用，防 GC
	wheelLastPointer int32   // 最近一次过手的真 WM_POINTERWHEEL 时间戳（双递防护）
)

// handlePlatformEvent 事件循环挂钩：窗口建立时拿 HWND 并子类化。
func handlePlatformEvent(e event.Event) {
	if v, ok := e.(app.Win32ViewEvent); ok {
		installWheelFix(v.HWND)
	}
}

// installWheelFix 子类化窗口（幂等）。失败静默：滚轮维持上游现状（不可
// 滚），不阻断窗口启动——这是可达性增强，不是主流程依赖。
func installWheelFix(hwnd uintptr) {
	if hwnd == 0 || wheelCallback != 0 {
		return
	}
	wheelCallback = windows.NewCallback(wheelProc)
	prev, _, _ := procSetWindowLongPtrW.Call(hwnd, gwlpWndProc, wheelCallback)
	wheelPrevProc = prev
	_ = procGetWindowLongPtrW // 保留符号：将来校验子类化成败用
}

// wheelProc 新窗口过程：滚轮消息先转译再入原链，其余一律原样放行。
func wheelProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmPointerWheel, wmPointerHWheel:
		// 真指针滚轮过手记录时间戳，供双递防护判定
		wheelLastPointer = getMessageTime()
	case wmMouseWheel, wmMouseHWheel:
		if mousePointerAvailable() {
			if out, w, ok := translateWheelMsg(msg, wParam, wheelLastPointer, getMessageTime()); ok {
				return callWindowProc(wheelPrevProc, hwnd, out, w, lParam)
			}
		}
	}
	return callWindowProc(wheelPrevProc, hwnd, msg, wParam, lParam)
}

// mousePointerAvailable 自测 GetPointerInfo(0)（鼠标指针 ID 恒为 0）：
// 失败说明系统无指针输入栈，转译出的 WM_POINTERWHEEL 会走进 gio
// scrollEvent 的 GetPointerInfo 失败即 panic 分支（os_windows.go:684）——
// 此时放弃转译，维持原行为（滚轮无效但不崩）。
func mousePointerAvailable() bool {
	var buf [128]byte // POINTER_INFO 实际约 104B，128B 兜底
	r, _, _ := procGetPointerInfo.Call(0, uintptr(unsafe.Pointer(&buf[0])))
	return r != 0
}

func callWindowProc(prev, hwnd, msg, wParam, lParam uintptr) uintptr {
	r, _, _ := procCallWindowProcW.Call(prev, hwnd, msg, wParam, lParam)
	return r
}

func getMessageTime() int32 {
	r, _, _ := procGetMessageTime.Call()
	return int32(r)
}
