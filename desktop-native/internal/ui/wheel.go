package ui

// wheel.go —— 标准鼠标滚轮修复的纯转译逻辑（与平台管线分离，可单测）。
//
// 根因（视觉验收 2026-10-06 实锤）：gioui.org@v0.10.3 的窗口过程只处理
// WM_POINTERWHEEL/WM_POINTERHWHEEL（app/os_windows.go:361-364），标准鼠标
// 滚轮消息 WM_MOUSEWHEEL/WM_MOUSEHWHEEL（0x20A/0x20E）整体落入
// DefWindowProc 被丢弃——工具页/结果页过程表/暴露面卡片列表三处 List 的
// 滚轮全部不可达。上游无修复版（v0.10.3 即最新 tag，无 0x20A 分支）。
//
// 修法：应用层子类化窗口过程（wheel_windows.go），把鼠标滚轮消息转译成
// gio 已处理的指针滚轮消息再交给原窗口过程。两条硬约束：
//   - WM_POINTERWHEEL 的 wParam 低 16 位是「指针 ID」（鼠标固定为 0）、
//     高 16 位是滚轮增量；WM_MOUSEWHEEL 的低 16 位是 MK_* 按键位。转译时
//     低 16 位清零，按键状态由 gio 侧 GetPointerInfo(0)（真实鼠标指针
//     状态）补全——绕开其 scrollEvent 对 GetPointerInfo 失败即 panic 的
//     路径（os_windows.go:684），不喂无效指针 ID。
//   - 双递防护：精准触摸板等指针栈设备可能同刻下发两种滚轮消息，30ms 内
//     已见过真 WM_POINTERWHEEL 就不再转译，避免滚一格走两格。

const (
	wmMouseWheel    uintptr = 0x020A // WM_MOUSEWHEEL
	wmMouseHWheel   uintptr = 0x020E // WM_MOUSEHWHEEL
	wmPointerWheel  uintptr = 0x024E
	wmPointerHWheel uintptr = 0x024F

	// wheelDedupMs 双递防护窗（毫秒）：同一物理滚轮刻的两种消息相隔 <1 个
	// 消息时间戳抖动，30ms 足够覆盖且不影响连续滚动（人手最快 ~8ms/格）。
	wheelDedupMs uint32 = 30
)

// translateWheelMsg 把标准鼠标滚轮消息转译为指针滚轮消息。
// 返回 ok=false 表示不转译（调用方把原消息原样放行）。
// lastPointerMs/nowMs 为 GetMessageTime 口径的毫秒时间戳（int32 可环绕）。
func translateWheelMsg(msg, wParam uintptr, lastPointerMs, nowMs int32) (outMsg, outWParam uintptr, ok bool) {
	if msg != wmMouseWheel && msg != wmMouseHWheel {
		return msg, wParam, false
	}
	if lastPointerMs != 0 && uint32(nowMs-lastPointerMs) <= wheelDedupMs {
		return msg, wParam, false
	}
	out := wmPointerWheel
	if msg == wmMouseHWheel {
		out = wmPointerHWheel
	}
	// 低 16 位清零：MK_* 按键位换成指针 ID 0（= 鼠标指针）
	return out, wParam &^ 0xffff, true
}
