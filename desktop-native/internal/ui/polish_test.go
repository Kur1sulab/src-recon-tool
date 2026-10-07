package ui

// polish_test.go — 打磨轮（2026-10-06）修复回归。验收口径：纯代码+单测，
// 不起 GUI 不截图；可视化条目（对齐/间距/钳高的观感）走 docs/人工目验清单.md。
//
// 覆盖：
//   - envInfo mock 探测生命周期（第 2 步直调重写后 env 仅剩 mock 一项）；
//   - baselineTargetKey 输入非法即时原因（不再静默退回空态）；
//   - pollBaseline 任务终态横条（失败/被停止在暴露面页有呈现，「已开始」清掉）；
//   - expireStopErr / expireNewBanners 横条生命周期；
//   - baselinePhaseColor LED 语义（skipped=警示橙、conclusion 跟结论等级）；
//   - 用户可见错误文案冒号统一全角。

import (
	"strings"
	"testing"

	"recon-native/internal/store"
)

func TestEnvInfoMockLifecycle(t *testing.T) {
	var e envInfo
	mock, probed := e.snapshot()
	if mock || probed {
		t.Fatalf("未探测时不得报可达/已探测: mock=%v probed=%v", mock, probed)
	}
	e.setMock(false) // 后台探测回：不可达
	mock, probed = e.snapshot()
	if !probed {
		t.Fatal("setMock 后 probed 应置位（否则页面永远停在「检测中…」）")
	}
	if mock {
		t.Fatal("不可达时 mock 应为 false")
	}
	e.setMock(true)
	mock, probed = e.snapshot()
	if !mock || !probed {
		t.Fatalf("可达后应双置位: mock=%v probed=%v", mock, probed)
	}
}

func TestBaselineTargetKeyInvalidReason(t *testing.T) {
	a := newAppUI(newTestSession(t))

	// 未输入：键与原因都空（空态引导卡只给真未输入）
	a.baseTargetEd.SetText("")
	if key, reason := a.baselineTargetKey(); key != "" || reason != "" {
		t.Fatalf("未输入应得键与原因全空: key=%q reason=%q", key, reason)
	}

	// 输入非法（带协议/端口）：键空但原因非空（输入井下方即时提示）
	for _, bad := range []string{"http://xycovo.com", "xycovo.com:443", "xycovo.com/admin"} {
		a.baseTargetEd.SetText(bad)
		key, reason := a.baselineTargetKey()
		if key != "" || reason == "" {
			t.Fatalf("非法输入 %q 应得 key=\"\" reason 非空: key=%q reason=%q", bad, key, reason)
		}
		if !strings.Contains(reason, "域名") {
			t.Fatalf("原因应说明应为域名: %q", reason)
		}
	}

	// 合法域名：键归一、原因空
	a.baseTargetEd.SetText("xycovo.com")
	if key, reason := a.baselineTargetKey(); key != "xycovo.com" || reason != "" {
		t.Fatalf("合法域名应放行: key=%q reason=%q", key, reason)
	}
}

func TestPollBaselineTerminalBanner(t *testing.T) {
	a := newAppUI(newTestSession(t))
	a.baseTargetEd.SetText("xycovo.com")
	a.tasks = []store.Task{{
		ID: "t1", Target: "xycovo.com", Cmd: "baseline",
		Status: store.StatusFail, CreatedAt: 100,
	}}
	a.baseOK = "基线检查已开始：t1"

	a.pollBaseline()
	if a.baseTerm == "" || !strings.Contains(a.baseTerm, "失败") {
		t.Fatalf("失败终态应有横条: %q", a.baseTerm)
	}
	if a.baseOK != "" {
		t.Fatalf("任务终态后「已开始」横条应清掉: %q", a.baseOK)
	}
	if a.baseTermID != "t1" {
		t.Fatalf("终态横条应记任务 id 去重: %q", a.baseTermID)
	}

	// 同一任务重复节拍：横条稳定不闪没、不重写
	a.pollBaseline()
	if !strings.Contains(a.baseTerm, "失败") {
		t.Fatalf("重复节拍不得清终态横条: %q", a.baseTerm)
	}

	// 换目标输入：终态横条随锚失效
	a.baseTargetEd.SetText("test.invalid")
	a.pollBaseline()
	if a.baseTerm != "" {
		t.Fatalf("换目标后终态横条应清空: %q", a.baseTerm)
	}
}

func TestPollBaselineStoppedAndRunningStates(t *testing.T) {
	a := newAppUI(newTestSession(t))
	a.baseTargetEd.SetText("xycovo.com")
	a.tasks = []store.Task{{
		ID: "t2", Target: "xycovo.com", Cmd: "baseline",
		Status: store.StatusStopped, CreatedAt: 100,
	}}
	a.baseOK = "基线检查已开始：t2"
	a.pollBaseline()
	if a.baseTerm == "" || !strings.Contains(a.baseTerm, "停止") {
		t.Fatalf("被停止终态应有横条: %q", a.baseTerm)
	}
	if a.baseOK != "" {
		t.Fatalf("「已开始」横条应清掉: %q", a.baseOK)
	}

	// 运行中：无终态横条（逐检查点亮是运行态的呈现）
	a.tasks[0].Status = store.StatusRunning
	a.baseTerm, a.baseTermID = "", ""
	a.pollBaseline()
	if a.baseTerm != "" {
		t.Fatalf("运行中不得出终态横条: %q", a.baseTerm)
	}

	// done：卡片逐检查结论即呈现，无终态横条，但「已开始」仍要清
	a.tasks[0].Status = store.StatusDone
	a.baseOK = "基线检查已开始：t2"
	a.pollBaseline()
	if a.baseTerm != "" {
		t.Fatalf("done 不得出终态横条: %q", a.baseTerm)
	}
	if a.baseOK != "" {
		t.Fatalf("done 后「已开始」横条应清掉: %q", a.baseOK)
	}
}

func TestExpireStopErr(t *testing.T) {
	s := newTestSession(t)
	id, err := s.CreateTask("xycovo.com", "icp", "")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	// 强制终态（绕开异步 monitor 时序：终态不回退语义保证后续 SetStatus 不覆盖）
	if err := s.Store.Update(id, func(tt *store.Task) { tt.Status = store.StatusStopped }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	a := newAppUI(s)
	a.selID = id
	a.stopErr = "停止失败：任务未在运行"
	a.expireStopErr()
	if a.stopErr != "" {
		t.Fatalf("选中任务已终态，停止回执应失效: %q", a.stopErr)
	}

	// 运行中任务：回执保留
	id2, err := s.CreateTask("test.invalid", "icp", "")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if err := s.Store.Update(id2, func(tt *store.Task) { tt.Status = store.StatusRunning }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	a.selID = id2
	a.stopErr = "停止失败：x"
	a.expireStopErr()
	if a.stopErr == "" {
		t.Fatal("运行中任务的停止回执不应清")
	}

	// 空回执：无操作不炸
	a.selID = ""
	a.stopErr = ""
	a.expireStopErr()
}

func TestExpireNewBannersAnchor(t *testing.T) {
	a := newAppUI(newTestSession(t))
	a.targetEd.SetText("xycovo.com")
	a.argsEd.SetText("--ports 80")
	a.expireNewBanners() // 首帧建立锚点

	a.newOK = "任务已开始：t1"
	a.newErr = "e"
	a.expireNewBanners()
	if a.newOK == "" || a.newErr == "" {
		t.Fatal("输入未变时横条不得被误清")
	}

	// 任一输入变化即失效
	a.targetEd.SetText("test.invalid")
	a.expireNewBanners()
	if a.newOK != "" || a.newErr != "" {
		t.Fatalf("目标变化后横条应清空: ok=%q err=%q", a.newOK, a.newErr)
	}

	// 模块变化同款
	a.targetEd.SetText("xycovo.com")
	a.expireNewBanners()
	a.newOK = "任务已开始：t2"
	a.moduleSel.Value = "icp"
	a.expireNewBanners()
	if a.newOK != "" {
		t.Fatalf("模块变化后横条应清空: %q", a.newOK)
	}
}

func TestBaselinePhaseLedColor(t *testing.T) {
	cases := []struct {
		phase, level string
		want         colorNRGBA
	}{
		{"running", "", ColAccHi},
		{"skipped", "", ColWarn}, // 已跳过=警示橙（曾归故障红，与卡顶橙条打架）
		{"failed", "", ColErr},   // 执行失败仍故障红
		{"conclusion", "ok", ColOk},
		{"conclusion", "warn", ColWarn},
		{"conclusion", "fail", ColErr}, // fail 级结论 LED 跟族色（曾恒绿点+红条双信号）
		{"conclusion", "info", ColAccHi},
		{"conclusion", "", ColTx2}, // 等级缺失按默认档（不编造绿）
		{"queued", "", ColTx3},
		{"notrun", "", ColTx3},
	}
	for _, c := range cases {
		if got := baselinePhaseColor(c.phase, c.level); got != c.want {
			t.Fatalf("baselinePhaseColor(%q,%q) = %v, 期望 %v", c.phase, c.level, got, c.want)
		}
	}
}

// TestUserErrorColonsFullWidth 用户可见错误文案冒号统一全角「：」。
func TestUserErrorColonsFullWidth(t *testing.T) {
	s := newTestSession(t)

	if _, err := s.CreateTask("xycovo.com", "poc", ""); err != nil {
		if !strings.Contains(err.Error(), "不支持的模块：") || strings.Contains(err.Error(), "不支持的模块: ") {
			t.Fatalf("模块错误冒号应全角: %q", err)
		}
	} else {
		t.Fatal("未知模块应拒绝")
	}

	if _, err := s.CreateTask("xycovo.com", "icp", "-d evil.com"); err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "可选参数不允许指定目标类参数：") || strings.Contains(msg, "参数: ") {
			t.Fatalf("目标旗标错误冒号应全角: %q", msg)
		}
	} else {
		t.Fatal("夹带目标旗标应拒绝")
	}

	if _, err := s.CreateTask("xycovo.com\nx", "paths", ""); err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "目标格式不合法：") || strings.Contains(msg, "目标格式不合法: ") {
			t.Fatalf("目标格式错误冒号应全角: %q", msg)
		}
	} else {
		t.Fatal("含控制字符的目标应拒绝")
	}

	if _, err := parseArgs("--bad~token"); err != nil {
		if !strings.Contains(err.Error(), "参数含不允许的字符：") {
			t.Fatalf("参数字符错误冒号应全角: %q", err)
		}
	} else {
		t.Fatal("非法字符参数应拒绝")
	}

	st := parseBaselineResult("secheaders", []byte("{broken"))
	if !strings.Contains(st.Error, "产物解析失败：") || strings.Contains(st.Error, "产物解析失败: ") {
		t.Fatalf("产物解析失败冒号应全角: %q", st.Error)
	}

	// engine.ValidateExtraArgs 的三条文案经 session.CreateTask（session.go
	// 参数闸）直达 UI 错误横条，冒号口径一并钉住。
	if _, err := s.CreateTask("xycovo.com", "paths", "--ports 80"); err != nil {
		if !strings.Contains(err.Error(), "该子命令不允许的旗标：") || strings.Contains(err.Error(), "旗标: ") {
			t.Fatalf("跨模块旗标错误冒号应全角: %q", err)
		}
	} else {
		t.Fatal("paths 不允许 --ports，应拒绝")
	}
	if _, err := s.CreateTask("xycovo.com", "paths", "ports"); err != nil {
		if !strings.Contains(err.Error(), "游离参数不允许：") || strings.Contains(err.Error(), "不允许: ") {
			t.Fatalf("游离参数错误冒号应全角: %q", err)
		}
	} else {
		t.Fatal("游离值 token 应拒绝")
	}
	if _, err := s.CreateTask("xycovo.com", "baseline", "--checks -secheaders"); err != nil {
		if !strings.Contains(err.Error(), "旗标取值不允许以 - 开头：") || strings.Contains(err.Error(), "开头: ") {
			t.Fatalf("旗标取值错误冒号应全角: %q", err)
		}
	} else {
		t.Fatal("取值以 - 开头应拒绝")
	}
}

func TestProbeChannelInitialized(t *testing.T) {
	a := newAppUI(newTestSession(t))
	if a.probeDone == nil || a.exportDone == nil {
		t.Fatal("probeDone/exportDone 回执通道必须初始化（后台探测/导出共用回执路径）")
	}
	if a.mockBusy {
		t.Fatal("初始不得处于忙态")
	}
}
