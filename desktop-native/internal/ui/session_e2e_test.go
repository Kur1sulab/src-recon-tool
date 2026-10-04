package ui

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"recon-native/internal/engine"
	"recon-native/internal/store"
)

// mockReady 报告白名单内本机 mock 靶站（127.0.0.1:8799）是否可达。
func mockReady() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:8799", 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestEndToEndMockTarget 端到端：白名单内 mock 靶站 → 真实引擎子进程 →
// 任务跑完 → 结果行可展示。这是新建任务页按钮背后那条链路的自动化验证
// （界面壳只做输入采集，语义完全等同 CreateTask → 结果表格）。
//
// 运行前提（缺一自动跳过，不让套件变红）：
//  1. 仓库根存在 src/recon.py；
//  2. Python + requests/yaml 可用；
//  3. mock 靶站已起：在仓库根跑 python tests/mock_server.py（监听 127.0.0.1:8799）。
func TestEndToEndMockTarget(t *testing.T) {
	repoRoot := findRepoRoot()
	if _, err := os.Stat(filepath.Join(repoRoot, "src", "recon.py")); err != nil {
		t.Skipf("仓库根没有 src/recon.py（repoRoot=%s），跳过端到端", repoRoot)
	}
	probe := engine.NewRunner(repoRoot, t.TempDir(), "")
	if found, _, depsOK := probe.ProbePython(); !found || !depsOK {
		t.Skip("python 或依赖（requests/yaml）不可用，跳过端到端")
	}
	if !mockReady() {
		t.Skip("mock 靶站未起（python tests/mock_server.py），跳过端到端")
	}

	// 真实会话：真任务库（临时目录）+ 真引擎，不注入任何假件
	s, err := NewSession(repoRoot, t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// 新建任务页同款输入：URL 模块打 mock 的 /real 场景
	id, err := s.CreateTask("http://127.0.0.1:8799/real", "api", "")
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
