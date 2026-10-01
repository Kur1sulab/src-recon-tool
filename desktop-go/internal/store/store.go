// Package store 提供任务持久化（tasks.json）与内存态任务表。
// 所有读写由一把互斥锁保护；每次变更原子落盘（临时文件 + rename）。
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// 任务状态机：created → running → done | fail | stopped
const (
	StatusCreated = "created"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFail    = "fail"
	StatusStopped = "stopped"
)

// MaxProgress 单任务进度事件上限（防失控膨胀）。
const MaxProgress = 2000

// ProgressEvent 与 Python 侧 _emit 的事件契约一一对应：
// {"ts":float,"event":str,"module":str,"detail":str}
type ProgressEvent struct {
	Ts     float64 `json:"ts"`
	Module string  `json:"module"`
	Event  string  `json:"event"`
	Detail string  `json:"detail"`
}

// Task 一次扫描任务的完整状态。
type Task struct {
	ID           string          `json:"id"`
	Target       string          `json:"target"`
	Cmd          string          `json:"cmd"`
	Args         string          `json:"args,omitempty"`
	Status       string          `json:"status"`
	CreatedAt    float64         `json:"created_at"`
	FinishedAt   float64         `json:"finished_at,omitempty"`
	ExitCode     *int            `json:"exit_code"`
	LogPath      string          `json:"log_path,omitempty"`
	ProgressPath string          `json:"progress_path,omitempty"`
	EvidencePath string          `json:"evidence_path,omitempty"`
	Progress     []ProgressEvent `json:"progress,omitempty"`
}

// Store 任务库。path 为空时纯内存（测试用）。
type Store struct {
	mu    sync.Mutex
	path  string
	tasks map[string]*Task
}

// Open 打开（或初始化）任务库；文件损坏时兜底为空库，绝不让桌面端起不来。
func Open(path string) (*Store, error) {
	s := &Store{path: path, tasks: make(map[string]*Task)}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	var list []*Task
	if err := json.Unmarshal(data, &list); err != nil {
		return s, nil // 坏文件 → 空库
	}
	recovered := false
	now := float64(time.Now().UnixMilli()) / 1e3
	for _, t := range list {
		if t == nil || t.ID == "" {
			continue
		}
		// 崩溃恢复：上次的 running 进程已随应用退出，对账为终态——
		// 否则任务永远卡在"运行中"，stop 也只能撞进程表缺失。
		if t.Status == StatusRunning {
			t.Status = StatusFail
			t.FinishedAt = now
			code := -1
			t.ExitCode = &code
			t.Progress = append(t.Progress, ProgressEvent{
				Ts: now, Module: "pipeline", Event: "pipeline_end",
				Detail: "fail（应用重启，任务中断）",
			})
			recovered = true
		}
		s.tasks[t.ID] = t
	}
	if recovered {
		_ = s.saveLocked() // Open 阶段尚无并发，直接落盘
	}
	return s, nil
}

// Create 新增任务（同 ID 覆盖视为错误）。
func (s *Store) Create(t *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.tasks[t.ID]; dup {
		return errors.New("任务 ID 重复: " + t.ID)
	}
	cp := *t
	s.tasks[t.ID] = &cp
	return s.saveLocked()
}

// Get 返回任务副本。
func (s *Store) Get(id string) (Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return Task{}, false
	}
	return *t, true
}

// List 全量任务，created_at 倒序（最新在前）。
func (s *Store) List() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Update 原子读改写单个任务；id 不存在返回错误。
func (s *Store) Update(id string, fn func(*Task)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return errors.New("任务不存在: " + id)
	}
	fn(t)
	s.saveLocked()
	return nil
}

// AppendProgress 追加进度事件（封顶 MaxProgress，丢最旧的）。
func (s *Store) AppendProgress(id string, evs []ProgressEvent) {
	if len(evs) == 0 {
		return
	}
	_ = s.Update(id, func(t *Task) {
		t.Progress = append(t.Progress, evs...)
		if over := len(t.Progress) - MaxProgress; over > 0 {
			t.Progress = t.Progress[over:]
		}
	})
}

// RunningIDs 所有 running 状态的任务 ID（关窗确认用）。
func (s *Store) RunningIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id, t := range s.tasks {
		if t.Status == StatusRunning {
			out = append(out, id)
		}
	}
	return out
}

// saveLocked 落盘（调用方持锁）。临时文件 + rename 保证原子性。
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt > list[j].CreatedAt })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
