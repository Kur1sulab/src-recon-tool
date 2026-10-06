package ui

// fix4_test.go — 仪表盘验收轮（2026-10-06）修复回归：
//   - 用户可见文案零授权/白名单字样（产品铁律；上轮 art4 全量清扫的漏网处
//     在 parseArgs 的目标旗标分支，经 CreateTask→newErr→errBanner 上屏）；
//   - 结果页分页条初值=第 1 页（listPage/rowsPage 零值起步显示「第 0 / 1 页」）；
//   - 暴露面页成功/错误横条属「一次输入的尝试」，目标输入变化即失效
//     （旧目标任务号横条挂在别的目标下易误读——验收 p6-cards78）。

import (
	"strings"
	"testing"
)

func TestParseArgsTargetFlagNoWhitelistWording(t *testing.T) {
	for _, args := range []string{"-t x", "--target evil.com", "--domain=evil.com", "-d evil.com"} {
		_, err := parseArgs(args)
		if err == nil {
			t.Fatalf("可选参数 %q 指定目标类旗标应拒绝", args)
		}
		msg := err.Error()
		if strings.Contains(msg, "白名单") || strings.Contains(msg, "授权") {
			t.Fatalf("用户可见文案不得出现授权/白名单字样: %q", msg)
		}
		// 文案要点名问题 token，用户才知道删哪段
		first := strings.Fields(args)[0]
		if !strings.Contains(msg, first) {
			t.Fatalf("文案应点名违规旗标 %q: %q", first, msg)
		}
	}
}

func TestNewAppUIPagerPagesStartAtOne(t *testing.T) {
	a := newAppUI(newTestSession(t))
	if a.listPage != 1 || a.rowsPage != 1 {
		t.Fatalf("分页条初值应为第 1 页: listPage=%d rowsPage=%d", a.listPage, a.rowsPage)
	}
}

func TestPollBaselineClearsStaleBannersOnTargetInput(t *testing.T) {
	a := newAppUI(newTestSession(t))

	// 换目标输入：旧横条（含旧目标任务号）必须清空
	a.baseTargetEd.SetText("xycovo.com")
	a.baseOK = "基线检查已开始：old-task-id"
	a.baseErr = "旧错误"
	a.pollBaseline()
	if a.baseOK != "" || a.baseErr != "" {
		t.Fatalf("换目标后旧横条应清空: ok=%q err=%q", a.baseOK, a.baseErr)
	}

	// 同一目标重复节拍：不清（正常使用中的横条不能闪没）。
	// 时序对齐真实帧序：输入变化帧先过一次节拍（同步锚点），点击设横条
	// 发生在输入稳定之后，后续节拍不得误清。
	a.baseTargetEd.SetText("test.invalid")
	a.pollBaseline()
	a.baseOK = "基线检查已开始：id-1"
	a.baseErr = "e-1"
	a.pollBaseline()
	a.pollBaseline()
	if a.baseOK != "基线检查已开始：id-1" || a.baseErr != "e-1" {
		t.Fatalf("同一目标重复节拍不应清横条: ok=%q err=%q", a.baseOK, a.baseErr)
	}

	// 清空目标输入：横条一并清空
	a.baseTargetEd.SetText("")
	a.pollBaseline()
	if a.baseOK != "" || a.baseErr != "" {
		t.Fatalf("清空目标后横条应清空: ok=%q err=%q", a.baseOK, a.baseErr)
	}
}
