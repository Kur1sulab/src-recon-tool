package ui

// baseline_inval_test.go — 视觉验收实锤的回归位：Gio 是事件驱动帧，
// update 里的 400ms 数据轮询只在 FrameEvent 里跑；任务终态/进度事件在
// 后台变化时没人请求帧，按钮/状态就停在旧帧（实测：任务已 done、按钮
// 仍「检查进行中…」直到下一次鼠标事件）。修法 = 后台节拍对任务库快照
// 做签名，变化即 Invalidate。taskStoreSignature 是签名纯函数。

import (
	"testing"

	"recon-native/internal/store"
)

func TestTaskStoreSignature(t *testing.T) {
	mk := func(status string, nProgress int) store.Task {
		tk := store.Task{ID: "a", Status: status, CreatedAt: 1}
		for i := 0; i < nProgress; i++ {
			tk.Progress = append(tk.Progress, store.ProgressEvent{
				Ts: float64(i), Module: "m", Event: "start", Detail: ""})
		}
		return tk
	}
	// 同一快照同签名（节拍内不空转重绘）
	s1 := taskStoreSignature([]store.Task{mk("running", 3)})
	s2 := taskStoreSignature([]store.Task{mk("running", 3)})
	if s1 != s2 {
		t.Fatal("相同快照应得相同签名（否则每 400ms 空转重绘）")
	}
	// 状态变化 → 签名变化（终态刷新触发条件）
	if s1 == taskStoreSignature([]store.Task{mk("done", 3)}) {
		t.Fatal("任务终态变化应改变签名")
	}
	// 进度事件追加 → 签名变化（运行中逐检查点亮的触发条件）
	if s1 == taskStoreSignature([]store.Task{mk("running", 4)}) {
		t.Fatal("进度事件追加应改变签名")
	}
	// 新任务出现 / 任务删除 → 签名变化
	if s1 == taskStoreSignature([]store.Task{mk("running", 3), mk("done", 0)}) {
		t.Fatal("任务增删应改变签名")
	}
	if s1 == taskStoreSignature(nil) {
		t.Fatal("空库与有任务应不同签名")
	}
}
