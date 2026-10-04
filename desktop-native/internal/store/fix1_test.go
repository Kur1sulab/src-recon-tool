package store

// fix1_test.go — 崩溃恢复：应用异常退出后 tasks.json 里的 running 任务
// 重启时必须对账为终态，否则永远卡在"运行中"且 Esc/停止都无法清除。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRecoversStaleRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.json")
	list := []*Task{
		{ID: "crash-1", Target: "xycovo.com", Cmd: "icp", Status: StatusRunning, CreatedAt: 100},
		{ID: "ok-1", Target: "xycovo.com", Cmd: "icp", Status: StatusDone, CreatedAt: 90},
	}
	data, _ := json.Marshal(list)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("crash-1")
	if !ok {
		t.Fatal("crash-1 应存在")
	}
	if got.Status != StatusFail {
		t.Fatalf("崩溃残留 running 应对账为 fail, 得 %q", got.Status)
	}
	if got.FinishedAt <= 0 {
		t.Fatal("对账任务应有 FinishedAt")
	}
	if got.ExitCode == nil || *got.ExitCode != -1 {
		t.Fatalf("对账任务 ExitCode 应为 -1, 得 %v", got.ExitCode)
	}
	if n := len(got.Progress); n == 0 || got.Progress[n-1].Event != "pipeline_end" {
		t.Fatalf("对账任务应补 pipeline_end 收尾事件: %v", got.Progress)
	}
	// 终态任务原样保留
	if ok1, _ := s.Get("ok-1"); ok1.Status != StatusDone {
		t.Fatalf("终态任务不得被改写, 得 %q", ok1.Status)
	}

	// 复开仍是对账后的状态（已落盘）
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s2.Get("crash-1"); again.Status != StatusFail {
		t.Fatalf("复开后 crash-1 应仍为 fail, 得 %q", again.Status)
	}
}
