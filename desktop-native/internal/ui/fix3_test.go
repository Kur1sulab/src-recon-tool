package ui

// fix3_test.go — 终修轮回归：
//   1. CreateTask 执行目标 = 白名单归一化 key（校验值=执行值；双尾点等
//      等价写法不再以原始串进 argv，P3 卫生缺口收口）
//   2. url 类目标 host 归一、路径尾巴保留（mock 靶站 /real 必须活着）
//   3. 壳层首尾 Unicode 空白归一口径钉住（内嵌控制字符仍拒，P4 口径对齐）
//   4. 统计卡窄主区折两行的列数决策（P3）

import "testing"

func TestCreateTaskExecutesNormalizedKey(t *testing.T) {
	s := newTestSession(t)
	id, err := s.CreateTask("xycovo.com..", "icp", "")
	if err != nil {
		t.Fatalf("双尾点等价写法应放行: %v", err)
	}
	got, ok := s.Store.Get(id)
	if !ok {
		t.Fatal("任务应已入库")
	}
	if got.Target != "xycovo.com" {
		t.Fatalf("入库/执行目标应为白名单归一化 key, 得 %q", got.Target)
	}
}

func TestCreateTaskKeepsURLPathWithNormalizedHost(t *testing.T) {
	s := newTestSession(t)
	id, err := s.CreateTask("http://127.0.0.1:8799/real?x=1", "api", "")
	if err != nil {
		t.Fatalf("名单内 URL 应放行: %v", err)
	}
	got, _ := s.Store.Get(id)
	if got.Target != "http://127.0.0.1:8799/real?x=1" {
		t.Fatalf("host 归一化但路径/查询尾巴应保留, 得 %q", got.Target)
	}
	// 无路径的 URL：host 归一、scheme 保留
	id2, err := s.CreateTask("https://xycovo.com", "fingerprint", "")
	if err != nil {
		t.Fatalf("https 目标应放行: %v", err)
	}
	if got2, _ := s.Store.Get(id2); got2.Target != "https://xycovo.com" {
		t.Fatalf("https scheme 应保留, 得 %q", got2.Target)
	}
}

func TestCreateTaskWhitespaceContract(t *testing.T) {
	s := newTestSession(t)
	// 首尾空白（含 \r\n）归一后是名单内主机：放行，且执行目标为归一形态
	id, err := s.CreateTask(" xycovo.com\r\n", "icp", "")
	if err != nil {
		t.Fatalf("首尾空白归一后是名单内主机，应放行: %v", err)
	}
	if got, _ := s.Store.Get(id); got.Target != "xycovo.com" {
		t.Fatalf("执行目标应为归一形态, 得 %q", got.Target)
	}
	// 内嵌控制字符不过闸
	if _, err := s.CreateTask("xycovo\t.com", "icp", ""); err == nil {
		t.Fatal("内嵌控制字符应被拒绝")
	}
}

func TestStatColsNarrowWrap(t *testing.T) {
	cases := map[int]int{
		0:   4, // 宽度未知按宽处置
		756: 4, // 恰容一行（4×180+3×12）
		755: 2, // 差 1dp 即折两行
		420: 2, // 两行 2+2 的最小舒适宽
		-1:  4, // 非法宽度按宽处置
	}
	for w, want := range cases {
		if got := statCols(w); got != want {
			t.Fatalf("statCols(%d) = %d, 期望 %d", w, got, want)
		}
	}
}
