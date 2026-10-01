package store

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func tempStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tasks.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestCreateAndGetRoundtrip(t *testing.T) {
	s := tempStore(t)
	code := 0
	err := s.Create(&Task{ID: "t1", Target: "xycovo.com", Cmd: "api", Args: "--fast",
		Status: StatusCreated, CreatedAt: 100, ExitCode: &code})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok := s.Get("t1")
	if !ok {
		t.Fatal("Get(t1) 未找到")
	}
	if got.Target != "xycovo.com" || got.Cmd != "api" || got.Status != StatusCreated {
		t.Fatalf("字段不回读: %+v", got)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Fatalf("ExitCode 应为 0: %+v", got.ExitCode)
	}
}

func TestGetUnknown(t *testing.T) {
	s := tempStore(t)
	if _, ok := s.Get("nope"); ok {
		t.Fatal("不存在的 id 不应命中")
	}
}

func TestListNewestFirst(t *testing.T) {
	s := tempStore(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Create(&Task{ID: id, Status: StatusCreated, CreatedAt: mapA[id]}); err != nil {
			t.Fatal(err)
		}
	}
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("List 长度 = %d, 期望 3", len(list))
	}
	if list[0].ID != "c" || list[2].ID != "a" {
		t.Fatalf("List 应按 created_at 倒序: %v", ids(list))
	}
}

var mapA = map[string]float64{"a": 1, "b": 2, "c": 3}

func ids(ts []Task) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

func TestUpdateAndAppendProgress(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(&Task{ID: "t1", Status: StatusCreated})
	s.AppendProgress("t1", []ProgressEvent{
		{Ts: 1, Module: "pipeline", Event: "pipeline_start", Detail: "api"},
		{Ts: 2, Module: "api", Event: "done", Detail: ""},
	})
	err := s.Update("t1", func(tk *Task) { tk.Status = StatusDone })
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.Get("t1")
	if got.Status != StatusDone {
		t.Fatalf("status = %s", got.Status)
	}
	if len(got.Progress) != 2 || got.Progress[1].Module != "api" {
		t.Fatalf("progress 未落: %+v", got.Progress)
	}
}

func TestProgressCapped(t *testing.T) {
	s := tempStore(t)
	_ = s.Create(&Task{ID: "t1", Status: StatusRunning})
	for i := 0; i < MaxProgress+500; i++ {
		s.AppendProgress("t1", []ProgressEvent{{Ts: float64(i), Module: "m", Event: "x"}})
	}
	got, _ := s.Get("t1")
	if len(got.Progress) > MaxProgress {
		t.Fatalf("progress 应封顶 %d, 实际 %d", MaxProgress, len(got.Progress))
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.json")
	s, _ := Open(path)
	_ = s.Create(&Task{ID: "keep", Target: "127.0.0.1:8799", Status: StatusCreated})
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("重开: %v", err)
	}
	if _, ok := s2.Get("keep"); !ok {
		t.Fatal("tasks.json 持久化丢失")
	}
}

func TestCorruptFileFallsBackToEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tasks.json")
	if err := writeFile(path, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("坏文件应兜底为空库而非报错: %v", err)
	}
	if n := len(s.List()); n != 0 {
		t.Fatalf("坏文件应得到空列表, 实际 %d", n)
	}
}
