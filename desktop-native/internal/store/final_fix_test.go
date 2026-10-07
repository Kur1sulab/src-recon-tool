package store

// final_fix_test.go — 集成终修轮验收（store 线）：
//  1. F2 数据界：进度单条 Detail 截断（此前 MaxProgress 只封条数不封单条
//     体积，实测单条 5MB Detail 把 tasks.json 撑到 5MB）；
//  2. F1 写放大：AppendProgress 落盘去抖——窗口内多次追加合并为一次落盘，
//     状态变更（Update）仍即时落盘并顺带持久化窗口内进度；
//  3. 退役幽灵字段：旧 tasks.json 里的 log_path/progress_path/evidence_path
//     读入不报错、下次落盘排出（Task 结构体已无这些字段）。
//
// 磁盘时序断言用注入的短去抖窗口（毫秒级），不 sleep 大常数。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withFastFlush(t *testing.T, d time.Duration) {
	t.Helper()
	old := progressFlushDelay
	progressFlushDelay = d
	t.Cleanup(func() { progressFlushDelay = old })
}

func TestAppendProgressTruncatesDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Create(&Task{ID: "t1", Status: StatusRunning})
	bomb := strings.Repeat("A", 5<<20)
	s.AppendProgress("t1", []ProgressEvent{{Ts: 1, Module: "m", Event: "bomb", Detail: bomb}})
	got, _ := s.Get("t1")
	if len(got.Progress) != 1 {
		t.Fatalf("应恰 1 条事件，得 %d", len(got.Progress))
	}
	d := got.Progress[0].Detail
	if len(d) <= MaxDetailLen {
		t.Fatalf("5MB Detail 应被截断到 %d 之上（含截断标记），实得 %d", MaxDetailLen, len(d))
	}
	if len(d) > MaxDetailLen+len("…（已截断）") || !strings.HasPrefix(d, "AAAA") {
		t.Fatalf("截断应保留前缀且只加固定尾巴：len=%d prefix=%q", len(d), d[:16])
	}
	// 落盘体积同步受控（等去抖窗口过后重开校验）
	withFastFlush(t, 10*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 64<<10 {
		t.Fatalf("截断后 tasks.json 应远小于炸弹体积，得 %d 字节", len(data))
	}
	if !json.Valid(data) {
		t.Fatal("tasks.json 应保持合法 JSON")
	}
}

func TestAppendProgressDebouncedFlush(t *testing.T) {
	withFastFlush(t, 30*time.Millisecond)
	path := filepath.Join(t.TempDir(), "tasks.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Create(&Task{ID: "t1", Status: StatusRunning})

	s.AppendProgress("t1", []ProgressEvent{{Ts: 1, Module: "m", Event: "evt-1", Detail: "first"}})
	// 窗口内：内存立即可见（UI 读内存），磁盘尚未写这批
	if got, _ := s.Get("t1"); len(got.Progress) != 1 {
		t.Fatalf("内存应即时可见，得 %d 条", len(got.Progress))
	}
	// 等去抖到期 → 一次落盘
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), "evt-1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("去抖窗口后进度应落盘（最后一次读到 err=%v）", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 连续 200 条追加 → 合并落盘：窗口内文件内容不逐条翻新（写放大消失）
	for i := 0; i < 200; i++ {
		s.AppendProgress("t1", []ProgressEvent{{Ts: float64(i + 10), Module: "m", Event: "burst"}})
	}
	if got, _ := s.Get("t1"); len(got.Progress) != 201 {
		t.Fatalf("内存应累计 201 条，得 %d", len(got.Progress))
	}
	time.Sleep(100 * time.Millisecond) // 等一次合并落盘
	data, _ := os.ReadFile(path)
	var list []Task
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("合并落盘后应为合法 JSON: %v", err)
	}
	if len(list) != 1 || len(list[0].Progress) != 201 {
		t.Fatalf("合并落盘应含全部 201 条进度，得 %+v", list)
	}
	// 状态变更即时落盘，并顺带持久化窗口内进度（终态不依赖去抖窗口）
	s.AppendProgress("t1", []ProgressEvent{{Ts: 999, Module: "m", Event: "tail", Detail: "pending"}})
	_ = s.Update("t1", func(tk *Task) { tk.Status = StatusDone })
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), "pending") {
		t.Fatal("Update 即时落盘应顺带持久化去抖窗口内的进度")
	}
}

func TestLegacyGhostFieldsExcretedOnSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tasks.json")
	legacy := `[{"id":"old1","target":"xycovo.com","cmd":"icp","status":"done",
	  "created_at":1,"exit_code":0,
	  "log_path":"logs/old1.log","progress_path":"progress/old1.jsonl","evidence_path":"evidence/old1.zip"}]`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("含幽灵字段的旧文件应正常打开: %v", err)
	}
	got, ok := s.Get("old1")
	if !ok || got.ID != "old1" || got.Status != StatusDone {
		t.Fatalf("旧任务应正常读入: %+v ok=%v", got, ok)
	}
	if err := s.Update("old1", func(t *Task) { t.Status = StatusFail }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, ghost := range []string{"log_path", "progress_path", "evidence_path"} {
		if strings.Contains(string(data), ghost) {
			t.Fatalf("重写后应排出退役幽灵字段 %s", ghost)
		}
	}
}
