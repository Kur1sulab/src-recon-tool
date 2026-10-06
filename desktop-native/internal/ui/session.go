// Package ui 桌面壳的界面与会话编排。会话层把「新建任务」按钮的语义
// 收敛成一次 CreateTask 调用：模块校验 → 目标卫生校验 → 目标形态归一
// → 可选参数校验 → 入库 → 起扫描子进程。目标全部默认授权（用户裁定
// 2026-10-05），本层只做格式卫生，不做任何名单判定。
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
	if settings.GoEnginePath != "" {
		r.SetGoEnginePath(settings.GoEnginePath)
	}
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
	// 目标卫生校验：控制字符/协议/端口/路径穿越一律拒绝（格式问题），
	// 目标本身全部默认授权（用户裁定 2026-10-05）。
	// 归一化 key 必须接住并作为入库/执行目标（对抗 P3 卫生缺口）：
	// 校验对象与执行对象一致——双尾点等「等价写法」不再以原始串进 argv。
	key, err := whitelist.Check(target)
	if err != nil {
		return "", fmt.Errorf("目标格式不合法: %w", err)
	}
	normalized, err := normalizeTarget(cmd, key, target)
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

// resolveGoEngineOrEmpty 返回当前解析到的 recon-go.exe 路径（失败空串，界面预填用）。
func (s *Session) resolveGoEngineOrEmpty() string {
	p, err := s.Runner.ResolveGoEngine()
	if err != nil {
		return ""
	}
	return p
}

// rebuildRunner 以当前 settings 换装引擎 runner（Python/Go 两条路径都按
// settings 带齐——换装丢字段曾会让另一条引擎路径静默回退到探测）。
func (s *Session) rebuildRunner(pythonPath string) {
	r := engine.NewRunner(s.RepoRoot, s.DataDir, pythonPath)
	if st, err := LoadSettings(s.DataDir); err == nil && st.GoEnginePath != "" {
		r.SetGoEnginePath(st.GoEnginePath)
	}
	r.SetSink(sessionSink{st: s.Store})
	s.Runner = r
}

// SetPythonPath 切换解释器并写回 settings.json（重启后仍生效）。
// 有任务运行时拒绝，避免丢进程表。GoEnginePath 字段原样保留。
func (s *Session) SetPythonPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("解释器路径不能为空")
	}
	if n := len(s.Runner.RunningIDs()); n > 0 {
		return fmt.Errorf("有 %d 个任务正在运行，等它们结束再切换解释器", n)
	}
	st, err := LoadSettings(s.DataDir)
	if err != nil {
		return fmt.Errorf("设置读取失败: %w", err)
	}
	st.PythonPath = path
	if err := SaveSettings(s.DataDir, st); err != nil {
		return fmt.Errorf("设置写入失败: %w", err)
	}
	s.rebuildRunner(path)
	return nil
}

// SetGoEnginePath 切换 recon-go.exe（基线检查执行器）路径并写回
// settings.json（样板同 SetPythonPath；PythonPath 字段原样保留）。
func (s *Session) SetGoEnginePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("Go 引擎路径不能为空")
	}
	if n := len(s.Runner.RunningIDs()); n > 0 {
		return fmt.Errorf("有 %d 个任务正在运行，等它们结束再切换 Go 引擎", n)
	}
	st, err := LoadSettings(s.DataDir)
	if err != nil {
		return fmt.Errorf("设置读取失败: %w", err)
	}
	st.GoEnginePath = path
	if err := SaveSettings(s.DataDir, st); err != nil {
		return fmt.Errorf("设置写入失败: %w", err)
	}
	s.rebuildRunner(st.PythonPath)
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

// normalizeTarget 按子命令校验目标形态并产出执行目标。
// 两段式（对抗 P3 卫生缺口）：形态约束（域/IP/URL 形态）看原始串 raw；
// 执行目标的 host 部分一律用白名单归一化的 key 重建——校验值=执行值，
// 双尾点等「等价写法」不再以原始串进 argv。url 类的 scheme 与路径/查询
// 尾巴保留自原始串：尾巴只属于已过闸的名单内主机，不影响白名单等价性
// （mock 靶站 http://127.0.0.1:8799/real 的 /real 必须活着）。
func normalizeTarget(cmd, key, raw string) (string, error) {
	isURLCmd := cmd == "api" || cmd == "paths" || cmd == "fingerprint" || cmd == "jsintel"
	lower := strings.ToLower(raw)
	switch {
	case isURLCmd:
		if i := strings.Index(raw, "://"); i >= 0 {
			rest := raw[i+3:]
			if j := strings.Index(rest, "/"); j >= 0 {
				return raw[:i+3] + key + rest[j:], nil
			}
			return raw[:i+3] + key, nil
		}
		return "http://" + key, nil
	case cmd == "reverse":
		if strings.ContainsAny(raw, "/:") || net.ParseIP(key) == nil {
			return "", fmt.Errorf("IP 反查的目标应为裸 IP 地址，如 47.100.49.228")
		}
		return key, nil
	case cmd == "subdomain" || cmd == "icp" || cmd == "baseline":
		if strings.ContainsAny(raw, "/:") {
			return "", fmt.Errorf("该模块的目标应为域名（不含协议和端口），如 xycovo.com")
		}
		return key, nil
	default: // all / portscan
		if strings.Contains(lower, "://") {
			return "", fmt.Errorf("该模块的目标应为域名或 IP（不含协议）")
		}
		return key, nil
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
			// 格式卫生口径（产品铁律：界面零授权/白名单字样）：目标类旗标
			// 一律由目标框注入，可选参数里出现同名/同义旗标按格式问题拒绝
			return nil, fmt.Errorf("可选参数不允许指定目标类参数: %s，目标请填在「扫描目标」框", tk)
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
