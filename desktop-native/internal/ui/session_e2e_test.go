package ui

// session_e2e_test.go — 端到端：真实会话（真任务库 + 真模块函数表）×
// engine-go/mockweb 本地靶站（127.0.0.1 httptest，零外网）。
// 第 2 步直调重写后不再依赖 Python/8799 外部 mock 进程，测试自建靶站。

import (
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"

	"recon-native/internal/store"
)

// TestEndToEndMockTarget 新建任务页按钮背后那条链路的自动化验证：
// CreateTask（界面壳只做输入采集，语义完全等同）→ 进程内直调 api 模块 →
// 打本地假站 → 任务终态 done → 结果表格可展示。
func TestEndToEndMockTarget(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()

	s, err := NewSession(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// 新建任务页同款输入：URL 模块打 mock 的 /real 场景
	id, err := s.CreateTask(srv.URL+"/real", "api", "")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	// 等任务终态（本机靶站 + 单模块，2 分钟足够）
	deadline := time.Now().Add(120 * time.Second)
	var task store.Task
	for {
		cur, ok := s.Task(id)
		if !ok {
			t.Fatal("任务丢失")
		}
		task = cur
		switch cur.Status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			goto terminal
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务 120 秒未到终态，状态 %q，进度 %d 条", cur.Status, len(cur.Progress))
		}
		time.Sleep(500 * time.Millisecond)
	}
terminal:

	// 结果页表格可见条目：过程行非空且收尾行存在
	rows := ResultRows(task)
	if len(rows) < 2 {
		t.Fatalf("结果表格应有 ≥2 行，得 %d 行；任务状态 %q", len(rows), task.Status)
	}
	if task.Status != store.StatusDone {
		t.Fatalf("mock 靶站上的 api 任务应完成，得 %q；行=%v", task.Status, rows)
	}
	endOK := false
	for _, r := range rows {
		if r.Event == "pipeline_end" {
			endOK = true
		}
	}
	if !endOK {
		t.Fatalf("过程记录缺 pipeline_end 收尾行: %v", rows)
	}

	// 结果行推导（任务列表也要能出这一条）
	if got := TaskRows(s.Tasks()); len(got) != 1 || got[0].ID != id {
		t.Fatalf("任务列表应含本次任务: %+v", got)
	}
}
