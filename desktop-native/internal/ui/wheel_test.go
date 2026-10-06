package ui

// wheel_test.go — 标准鼠标滚轮修复的消息转译纯函数回归。
// 背景（视觉验收 2026-10-06 实锤）：gioui.org@v0.10.3 窗口过程只处理
// WM_POINTERWHEEL/WM_POINTERHWHEEL（app/os_windows.go:361-364），标准鼠标
// 滚轮 WM_MOUSEWHEEL/WM_MOUSEHWHEEL（0x20A/0x20E）整体落入 DefWindowProc，
// 全应用 List 滚轮不可达；上游无修复版（v0.10.3 即最新 tag）。

import "testing"

func TestTranslateWheelMsg(t *testing.T) {
	// 垂直滚轮：转 WM_POINTERWHEEL，低 16 位清零（MK_* 键位 → 指针 ID 0=鼠标）
	out, w, ok := translateWheelMsg(wmMouseWheel, (120<<16)|0x0008, 0, 100)
	if !ok || out != wmPointerWheel || w != 120<<16 {
		t.Fatalf("垂直滚轮转译不符: out=%#x w=%#x ok=%v", out, w, ok)
	}
	// 水平滚轮：转 WM_POINTERHWHEEL
	out, _, ok = translateWheelMsg(wmMouseHWheel, 120<<16, 0, 100)
	if !ok || out != wmPointerHWheel {
		t.Fatalf("水平滚轮转译不符: out=%#x ok=%v", out, ok)
	}
	// 非滚轮消息：原样放行
	if _, _, ok = translateWheelMsg(0x0200, 0, 0, 100); ok {
		t.Fatal("WM_MOUSEMOVE 等非滚轮消息不应转译")
	}
	// 双递防护：30ms 内刚过手真指针滚轮（精准触摸板同刻下发两种消息），跳过
	if _, _, ok = translateWheelMsg(wmMouseWheel, 0, 100, 110); ok {
		t.Fatal("指针滚轮后 30ms 内的鼠标滚轮应跳过（双递防护）")
	}
	// 防护窗外：照常转译
	if _, _, ok = translateWheelMsg(wmMouseWheel, 0, 100, 200); !ok {
		t.Fatal("超过双递防护窗应照常转译")
	}
	// GetMessageTime 环绕语义（uint32 差值）：环绕 10ms 仍算防护窗内
	last := int32(2147483647)
	now := int32(-2147483639) // last+10ms 环绕后的值
	if _, _, ok = translateWheelMsg(wmMouseWheel, 0, last, now); ok {
		t.Fatal("环绕 10ms 应仍处防护窗内")
	}
}
