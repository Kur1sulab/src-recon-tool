// Package store 提供任务持久化（tasks.json）与内存态任务表。
// 所有读写由一把互斥锁保护；状态/结构变更即时原子落盘（临时文件 + rename），
// 进度事件落盘按 progressFlushDelay 去抖合并（终修轮 F1 写放大修复）。
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
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

// MaxDetailLen 单条进度事件 Detail 截断上限（终修轮 F2 数据界）：MaxProgress
// 只封条数不封单条体积，实测单条 5MB Detail 把 tasks.json 撑到 5MB。截断只
// 影响进度展示文案（证据正文在 out/ 产物，不依赖进度事件）；上限与 baseline
// secheaders 判定 note 的 4096 先例同值。
const MaxDetailLen = 4096

// progressFlushDelay 进度落盘去抖窗口（终修轮 F1 写放大修复）：此前每批
// 进度事件触发 tasks.json 全量重写（实测 1.11ms/条），洪水/多任务场景磁盘
// I/O 随事件数线性放大。进度是展示数据（内存即时可见；状态变更走 Update
// 即时落盘并顺带持久化窗口内进度），窗口内变更合并为一次落盘；测试注入
// 短窗口。窗口尾部数据在进程被硬杀（非正常收尾）时最多丢 500ms 展示进度，
// 不影响终态与对账。
var progressFlushDelay = 500 * time.Millisecond

// Delete 相关的可识别错误（server 层映射 HTTP 状态码）。
var (
	ErrNotFound   = errors.New("任务不存在")
	ErrTaskActive = errors.New("任务仍在运行，不能删除")
)

// ProgressEvent 与 Python 侧 _emit 的事件契约一一对应：
// {"ts":float,"event":str,"module":str,"detail":str}
type ProgressEvent struct {
	Ts     float64 `json:"ts"`
	Module string  `json:"module"`
	Event  string  `json:"event"`
	Detail string  `json:"detail"`
}

// Task 一次扫描任务的完整状态。（终修轮移除退役幽灵字段 LogPath/
// ProgressPath/EvidencePath——进度 JSONL Tailer 与日志文件管道随子进程壳
// 退役后零生产者；旧文件里的同名键读入时忽略、下次落盘自然排出。）
type Task struct {
	ID         string          `json:"id"`
	Target     string          `json:"target"`
	Cmd        string          `json:"cmd"`
	Args       string          `json:"args,omitempty"`
	Status     string          `json:"status"`
	CreatedAt  float64         `json:"created_at"`
	FinishedAt float64         `json:"finished_at,omitempty"`
	ExitCode   *int            `json:"exit_code"`
	Progress   []ProgressEvent `json:"progress,omitempty"`
}

// Store 任务库。path 为空时纯内存（测试用）。
type Store struct {
	mu    sync.Mutex
	path  string
	tasks map[string]*Task

	// 进度落盘去抖（终修轮 F1）：AppendProgress 只标脏 + 排一次定时器，
	// 窗口内多批事件合并为一次全量落盘。
	progDirty bool
	progTimer *time.Timer
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
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.progDirty = false // 本次落盘顺带持久化了去抖窗口内的进度
	return nil
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

// Update 原子读改写单个任务；id 不存在返回错误。状态/结构变更即时落盘，
// 并顺带持久化进度去抖窗口内的变更（终态不依赖去抖窗口）。
func (s *Store) Update(id string, fn func(*Task)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return errors.New("任务不存在: " + id)
	}
	fn(t)
	if err := s.saveLocked(); err == nil {
		s.progDirty = false
	}
	return nil
}

// AppendProgress 追加进度事件：封顶 MaxProgress（丢最旧的）、单条 Detail 超
// MaxDetailLen 截断（F2）；落盘去抖合并（F1）——内存即时生效（UI 读内存），
// 磁盘在窗口后一次写入。任务已不存在时静默丢弃（进度对已删任务无意义）。
func (s *Store) AppendProgress(id string, evs []ProgressEvent) {
	if len(evs) == 0 {
		return
	}
	norm := make([]ProgressEvent, len(evs))
	for i, ev := range evs {
		norm[i] = ev
		norm[i].Detail = truncateDetail(ev.Detail)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return
	}
	t.Progress = append(t.Progress, norm...)
	if over := len(t.Progress) - MaxProgress; over > 0 {
		t.Progress = t.Progress[over:]
	}
	if s.path != "" {
		s.progDirty = true
		if s.progTimer == nil {
			s.progTimer = time.AfterFunc(progressFlushDelay, s.flushProgress)
		}
	}
}

// flushProgress 去抖到期回调：把窗口内累计的进度变更一次性落盘；落盘失败
// 择期重试（脏标不清，下次追加或状态变更仍会带出）。
func (s *Store) flushProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.progTimer = nil
	if !s.progDirty {
		return
	}
	if err := s.saveLocked(); err != nil {
		s.progTimer = time.AfterFunc(progressFlushDelay, s.flushProgress)
		return
	}
	s.progDirty = false
}

// truncateDetail 单条 Detail 截断（rune 安全：逐字节回退半个 rune 尾巴）。
func truncateDetail(s string) string {
	if len(s) <= MaxDetailLen {
		return s
	}
	cut := s[:MaxDetailLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…（已截断）"
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

// Delete 删除任务记录及其数据目录文件（progress/<id>.jsonl、logs/<id>.log）。
// running/created 状态拒绝（ErrTaskActive → HTTP 409）；不存在的 id 返回 ErrNotFound → 404。
// 仓库 out/<目标>/ 下的扫描产物是用户资产，不在删除范围。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return ErrNotFound
	}
	if t.Status == StatusRunning || t.Status == StatusCreated {
		return ErrTaskActive
	}
	delete(s.tasks, id)
	if err := s.saveLocked(); err != nil {
		s.tasks[id] = t // 落盘失败回滚内存，保持一致
		return err
	}
	s.progDirty = false // 本次落盘顺带持久化了去抖窗口内的进度
	// 旧版子进程壳时代的残留文件（progress/<id>.jsonl、logs/<id>.log）顺手
	// 清理；缺失/只读不致命：任务记录已删，残留文件无害
	if s.path != "" {
		dataDir := filepath.Dir(s.path)
		_ = os.Remove(filepath.Join(dataDir, "progress", id+".jsonl"))
		_ = os.Remove(filepath.Join(dataDir, "logs", id+".log"))
	}
	return nil
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
