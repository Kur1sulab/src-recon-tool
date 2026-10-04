// Package ui 桌面壳的界面与会话编排。会话层把「新建任务」按钮的语义
// 收敛成一次 CreateTask 调用：模块白名单 → 正点名单硬校验 → 目标形态归一
// → 可选参数白名单 → 入库 → 起扫描子进程，与 desktop-go 的 server 层
// hCreate 同一套闸门顺序，白名单行为不变。
package ui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"recon-native/internal/engine"
	"recon-native/internal/store"
	"recon-native/internal/whitelist"
)

// Session 一次桌面会话的全部状态：任务库 + 引擎 runner + 路径。
type Session struct {
	Store    *store.Store
	Runner   *engine.Runner
	RepoRoot string
	DataDir  string
}

// NewSession 打开任务库并组装引擎 runner（引擎回调经 sink 回写任务库）。
// 解释器优先级：settings.json 里用户保存的路径 > 入参（通常来自
// RECON_PYTHON 环境变量）> PATH 探测。
func NewSession(repoRoot, dataDir, pythonPath string) (*Session, error) {
	st, err := store.Open(filepath.Join(dataDir, "tasks.json"))
	if err != nil {
		return nil, fmt.Errorf("打开任务库失败: %w", err)
	}
	settings, lerr := LoadSettings(dataDir)
	if lerr != nil {
		return nil, fmt.Errorf("读取设置失败: %w", lerr)
	}
	if settings.PythonPath != "" {
		pythonPath = settings.PythonPath
	}
	r := engine.NewRunner(repoRoot, dataDir, pythonPath)
	r.SetSink(sessionSink{st: st})
	return &Session{Store: st, Runner: r, RepoRoot: repoRoot, DataDir: dataDir}, nil
}

// sessionSink 引擎回调 → 任务库（终态不回退，与 desktop-go storeSink 同语义）。
type sessionSink struct{ st *store.Store }

func (s sessionSink) AppendProgress(id string, evs []store.ProgressEvent) {
	s.st.AppendProgress(id, evs)
}

func (s sessionSink) SetStatus(id, status string, exitCode *int) {
	_ = s.st.Update(id, func(t *store.Task) {
		switch t.Status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			return
		}
		t.Status = status
		t.ExitCode = exitCode
		switch status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			t.FinishedAt = float64(time.Now().UnixMilli()) / 1e3
		}
	})
}

// CreateTask 新建并启动一次扫描。任何一步校验失败都不入库。
func (s *Session) CreateTask(target, cmd, argsRaw string) (string, error) {
	target = strings.TrimSpace(target)
	cmd = strings.TrimSpace(cmd)
	if target == "" {
		return "", fmt.Errorf("缺少扫描目标")
	}
	if len(target) > 200 {
		return "", fmt.Errorf("目标过长（上限 200 字符）")
	}
	if !engine.CmdAllowed(cmd) {
		return "", fmt.Errorf("不支持的模块: %s", cmd)
	}
	// 白名单闸：名单外一律拒绝（正点名单硬校验，行为与 desktop-go 完全一致）
	if _, err := whitelist.Check(target); err != nil {
		return "", fmt.Errorf("目标不在授权白名单，已拒绝（允许: xycovo.com / 47.100.49.228 / 127.0.0.1:8799）")
	}
	normalized, err := normalizeTarget(cmd, target)
	if err != nil {
		return "", err
	}
	extra, err := parseArgs(argsRaw)
	if err != nil {
		return "", err
	}
	// 纵深层：按模块旗标精确白名单复检（堵 argparse 前缀缩写覆盖目标）
	if err := engine.ValidateExtraArgs(cmd, extra); err != nil {
		return "", err
	}

	id := genID()
	now := float64(time.Now().UnixMilli()) / 1e3
	task := &store.Task{
		ID:        id,
		Target:    normalized,
		Cmd:       cmd,
		Args:      strings.Join(extra, " "),
		Status:    store.StatusCreated,
		CreatedAt: now,
		LogPath:   filepath.Join(s.DataDir, "logs", id+".log"),
	}
	if err := s.Store.Create(task); err != nil {
		return "", fmt.Errorf("任务入库失败: %w", err)
	}
	if err := s.Runner.Start(id, cmd, normalized, extra); err != nil {
		_ = s.Store.Update(id, func(t *store.Task) {
			// 终态不回退：停止竞态已落 stopped 时不得改写成 fail
			switch t.Status {
			case store.StatusDone, store.StatusFail, store.StatusStopped:
				return
			}
			t.Status = store.StatusFail
			t.FinishedAt = float64(time.Now().UnixMilli()) / 1e3
			t.Progress = append(t.Progress, store.ProgressEvent{
				Ts: float64(time.Now().UnixMilli()) / 1e3, Module: "pipeline",
				Event: "pipeline_end", Detail: "fail",
			})
		})
		return "", fmt.Errorf("启动扫描失败: %w", err)
	}
	return id, nil
}

// StopTask 停止任务。进程表里已无此 ID（假进程早退/崩溃残留）按幂等成功处理。
func (s *Session) StopTask(id string) error {
	if _, ok := s.Store.Get(id); !ok {
		return fmt.Errorf("任务不存在或已被清理")
	}
	if err := s.Runner.Stop(id); err != nil && err != engine.ErrNotRunning {
		return err
	}
	return nil
}

// Tasks 最新在前。
func (s *Session) Tasks() []store.Task { return s.Store.List() }

// Task 单个任务。
func (s *Session) Task(id string) (store.Task, bool) { return s.Store.Get(id) }

// resolvePythonOrEmpty 返回当前解析到的解释器路径（失败返回空串，仅界面预填用）。
func (s *Session) resolvePythonOrEmpty() string {
	p, err := s.Runner.ResolvePython()
	if err != nil {
		return ""
	}
	return p
}

// SetPythonPath 切换解释器并写回 settings.json（重启后仍生效）。
// 有任务运行时拒绝，避免丢进程表。
func (s *Session) SetPythonPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("解释器路径不能为空")
	}
	if n := len(s.Runner.RunningIDs()); n > 0 {
		return fmt.Errorf("有 %d 个任务正在运行，等它们结束再切换解释器", n)
	}
	if err := SaveSettings(s.DataDir, Settings{PythonPath: path}); err != nil {
		return fmt.Errorf("设置写入失败: %w", err)
	}
	r := engine.NewRunner(s.RepoRoot, s.DataDir, path)
	r.SetSink(sessionSink{st: s.Store})
	s.Runner = r
	return nil
}

// mockReachable 探测本机 mock 靶站（127.0.0.1:8799，白名单内的授权目标）。
func mockReachable() bool {
	c := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := c.Get("http://127.0.0.1:8799/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// genID 生成任务 ID（与 desktop-go 同格式）。
func genID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// ── 目标归一与可选参数白名单（自 desktop-go/internal/server 同规则移植）──

var argsTokenRe = regexp.MustCompile(`^[A-Za-z0-9_.=,:/+@%^-]+$`)

// targetFlagTokens recon.py 各子解析器的目标旗标同义全集：目标只能由壳按
// 白名单校验后注入，可选参数里出现同名/同义旗标一律拒绝——否则 argparse
// "重复单值旗标后者胜"，用户参数可覆盖受控目标、扫到名单外资产。
var targetFlagTokens = map[string]bool{
	"-u": true, "--url": true, "-t": true, "--target": true,
	"-d": true, "--domain": true, "-i": true, "--ip": true,
}

// flagName 取旗标名（截掉 =value，小写）。
func flagName(tk string) string {
	if i := strings.IndexByte(tk, '='); i >= 0 {
		tk = tk[:i]
	}
	return strings.ToLower(tk)
}

// normalizeTarget 按子命令校验形态；url 类缺协议时补 http://。
func normalizeTarget(cmd, target string) (string, error) {
	isURLCmd := cmd == "api" || cmd == "paths" || cmd == "fingerprint" || cmd == "jsintel"
	lower := strings.ToLower(target)
	switch {
	case isURLCmd:
		if !strings.Contains(lower, "://") {
			return "http://" + target, nil
		}
		return target, nil
	case cmd == "reverse":
		if strings.ContainsAny(target, "/:") || net.ParseIP(target) == nil {
			return "", fmt.Errorf("IP 反查的目标应为裸 IP 地址，如 47.100.49.228")
		}
		return target, nil
	case cmd == "subdomain" || cmd == "icp":
		if strings.ContainsAny(target, "/:") {
			return "", fmt.Errorf("该模块的目标应为域名（不含协议和端口），如 xycovo.com")
		}
		return target, nil
	default: // all / portscan
		if strings.Contains(lower, "://") {
			return "", fmt.Errorf("该模块的目标应为域名或 IP（不含协议）")
		}
		return target, nil
	}
}

// parseArgs 把可选参数串切成 argv 白名单片段：限长、限量、限字符集，
// 并显式挡掉 --progress-file（由壳注入，用户不可覆盖）。
func parseArgs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 200 {
		return nil, fmt.Errorf("可选参数过长（上限 200 字符）")
	}
	tokens := strings.Fields(raw)
	if len(tokens) > 8 {
		return nil, fmt.Errorf("可选参数最多 8 段")
	}
	for _, tk := range tokens {
		lower := strings.ToLower(tk)
		if strings.HasPrefix(lower, "--progress-file") || strings.HasPrefix(lower, "--progress_file") ||
			lower == "-h" || lower == "--help" {
			return nil, fmt.Errorf("不允许的参数: %s", tk)
		}
		if targetFlagTokens[flagName(tk)] {
			return nil, fmt.Errorf("目标由系统按白名单校验后注入，不允许在可选参数中指定: %s", tk)
		}
		if !argsTokenRe.MatchString(tk) {
			return nil, fmt.Errorf("参数含不允许的字符: %s", tk)
		}
	}
	return tokens, nil
}

// findRepoRoot 从 exe 目录与工作目录向上找仓库根（src/recon.py 所在）。
func findRepoRoot() string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		for i := 0; i < 4; i++ {
			candidates = append(candidates, d)
			d = filepath.Dir(d)
		}
	}
	if d, err := os.Getwd(); err == nil {
		for i := 0; i < 4; i++ {
			candidates = append(candidates, d)
			d = filepath.Dir(d)
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "src", "recon.py")); err == nil {
			return c
		}
	}
	return "."
}

// dataDirPath 数据目录：%LOCALAPPDATA%/recon-native（退 UserConfigDir / 当前目录）。
func dataDirPath() string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "recon-native")
	}
	if base, err := os.UserConfigDir(); err == nil {
		return filepath.Join(base, "recon-native")
	}
	return ".recon-native"
}
