// Package engine 管理 recon.py 子进程：起停、进程树终止、进度 JSONL 游标解析、
// 原始日志落盘。Go 层是壳，扫描引擎仍是既有 Python 流水线（python src/recon.py <子命令>）。
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"recon-native/internal/store"
	"recon-native/internal/whitelist"
)

// cmdSet 允许下发的子命令白名单（与桌面端九模块一一对应）。
var cmdSet = map[string]bool{
	"all": true, "paths": true, "api": true, "fingerprint": true, "jsintel": true,
	"portscan": true, "subdomain": true, "reverse": true, "icp": true,
}

// Sink 引擎向任务库回写状态/进度的通道（server 侧实现，测试侧用假件）。
type Sink interface {
	AppendProgress(taskID string, evs []store.ProgressEvent)
	SetStatus(taskID, status string, exitCode *int)
}

// Runner 管理全部运行中的扫描进程。
type Runner struct {
	mu         sync.Mutex
	repoRoot   string
	dataDir    string
	pythonPath string
	procs      map[string]*exec.Cmd
	stopping   map[string]bool
	jobs       map[string]io.Closer // 任务 id → Job Object 句柄（Windows，随壳消亡）
	sink       Sink

	// 两个接缝：测试注入假进程 / 假 LookPath
	Command  func(name string, args ...string) *exec.Cmd
	LookPath func(file string) (string, error)
}

// NewRunner repoRoot=仓库根（src/recon.py 与 out/ 所在），dataDir=桌面端数据目录。
func NewRunner(repoRoot, dataDir, pythonPath string) *Runner {
	return &Runner{
		repoRoot:   repoRoot,
		dataDir:    dataDir,
		pythonPath: pythonPath,
		procs:      make(map[string]*exec.Cmd),
		stopping:   make(map[string]bool),
		jobs:       make(map[string]io.Closer),
		Command:    exec.Command,
		LookPath:   exec.LookPath,
	}
}

// SetSink 注入状态回写通道（须在 Start 之前）。
func (r *Runner) SetSink(s Sink) { r.sink = s }

func (r *Runner) sinkOrDefault() Sink {
	if r.sink == nil {
		return nopSink{}
	}
	return r.sink
}

type nopSink struct{}

func (nopSink) AppendProgress(string, []store.ProgressEvent) {}
func (nopSink) SetStatus(string, string, *int)               {}

// ErrNotRunning 任务不在运行（进程表无此 ID）。调用方（如 server 的 stop）
// 应按幂等成功处理：崩溃重启后 tasks.json 里残留的 running 任务进程已不存在。
var ErrNotRunning = errors.New("任务未在运行")

// ResolvePython 解析解释器：显式设置 > RECON_PYTHON 环境变量 > PATH（python → python3）。
func (r *Runner) ResolvePython() (string, error) {
	if r.pythonPath != "" {
		return r.pythonPath, nil
	}
	if env := os.Getenv("RECON_PYTHON"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
	}
	for _, name := range []string{"python", "python3"} {
		p, err := r.LookPath(name)
		if err != nil {
			continue
		}
		// Windows 商店占位程序（WindowsApps 存根）LookPath 可命中但运行必败，跳过
		if strings.Contains(strings.ToLower(p), "windowsapps") {
			continue
		}
		return p, nil
	}
	return "", errors.New("未找到 Python 解释器（可在设置里指定，或设 RECON_PYTHON 环境变量）")
}

// probeTimeout 单次自检子进程的上限：解释器挂起/启动极慢时宁可报
// 「自检超时」也不能把 Gio 事件循环无限期冻住（审计 low-3）。
const probeTimeout = 10 * time.Second

// runBounded 带超时跑一次子进程：超时树杀并返回错误（审计 low-3）。
// 经统一的 Command 接缝构造，测试假件不受影响。
func (r *Runner) runBounded(c *exec.Cmd, d time.Duration) error {
	if err := c.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		_ = killTree(c)
		<-done
		return fmt.Errorf("自检超时（%s）", d)
	}
}

// ProbePython 探测解释器可用性与关键依赖（requests/yaml），供设置页自检。
// 路径先解析并校验为真实存在的可执行文件，再经固定 argv 数组调用（无 shell
// 参与）；每次调用带超时上限（probeTimeout），挂起的解释器不会拖死 UI。
func (r *Runner) ProbePython() (found bool, version string, depsOK bool) {
	py, err := r.ResolvePython()
	if err != nil {
		return false, "", false
	}
	if abs, lerr := exec.LookPath(py); lerr == nil {
		py = abs
	}
	info, serr := os.Stat(py)
	if serr != nil || info.IsDir() {
		return false, "", false
	}
	found = true
	c := r.Command(py, "--version") // 固定参数数组，经统一进程接缝
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	if err := r.runBounded(c, probeTimeout); err == nil {
		version = strings.TrimSpace(buf.String())
	}
	dep := r.Command(py, "-c", "import requests, yaml") // 固定代码串 + 参数数组
	dep.Dir = r.repoRoot
	depsOK = r.runBounded(dep, probeTimeout) == nil
	return found, version, depsOK
}

// CmdAllowed 报告子命令是否在九模块白名单内。
func CmdAllowed(cmd string) bool { return cmdSet[cmd] }

// BuildCmdArgs 把子命令 + 目标拼成 recon.py 的参数段（不含解释器与脚本路径）。
// fix1 P0 纵深层：extra 过 ValidateExtraArgs 精确白名单（堵 argparse 前缀缩写
// 展开覆盖目标）——server 层黑名单之外的任何调用方也绕不过这里。
func BuildCmdArgs(cmd, target string, extra []string) ([]string, error) {
	if !cmdSet[cmd] {
		return nil, fmt.Errorf("不支持的子命令: %s", cmd)
	}
	if err := ValidateExtraArgs(cmd, extra); err != nil {
		return nil, err
	}
	var head []string
	switch cmd {
	case "all":
		head = []string{"all", "-t", target}
	case "portscan":
		head = []string{"portscan", "-t", target}
	case "subdomain":
		head = []string{"subdomain", "-d", target}
	case "icp":
		head = []string{"icp", "-d", target}
	case "reverse":
		head = []string{"reverse", "-i", target}
	case "api", "paths", "fingerprint", "jsintel":
		head = []string{cmd, "-u", target}
	}
	return append(head, extra...), nil
}

// taskIDRe 任务 id 形态：字母数字开头结尾，中间允许点/连字符/下划线，
// 全长 ≤80——id 会拼进 progress/log 文件路径，畸形 id 在引擎层就地拒绝。
var taskIDRe = regexp.MustCompile(`^[0-9A-Za-z]([0-9A-Za-z._-]{0,78}[0-9A-Za-z])?$`)

// Start 起一个扫描进程并挂上监视 goroutine。成功后任务状态置 running。
func (r *Runner) Start(id, cmd, target string, extra []string) error {
	// 引擎层纵深闸（终修轮，审计 adv-low-1）：正常流程里调用方
	// （session.CreateTask）已过目标格式校验与参数闸，但本层不信任该前提——
	// 未来任何新调用方直连 Start，也不至于把格式非法的目标送进扫描、把
	// 畸形 id 拼进 progress/log 文件路径。目标本身全部默认授权（用户裁定
	// 2026-10-05），本闸只做格式卫生。
	if _, err := whitelist.Check(target); err != nil {
		return fmt.Errorf("目标格式校验未通过: %w", err)
	}
	if !taskIDRe.MatchString(id) {
		return fmt.Errorf("任务 ID 含不允许的字符: %q", id)
	}
	python, err := r.ResolvePython()
	if err != nil {
		return err
	}
	argv, err := BuildCmdArgs(cmd, target, extra)
	if err != nil {
		return err
	}
	script := filepath.Join("src", "recon.py")
	if _, err := os.Stat(filepath.Join(r.repoRoot, script)); err != nil {
		return errors.New("未找到扫描引擎 src/recon.py（工作目录必须为仓库根）")
	}

	progressPath := filepath.Join(r.dataDir, "progress", id+".jsonl")
	logPath := filepath.Join(r.dataDir, "logs", id+".log")
	if err := os.MkdirAll(filepath.Dir(progressPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return err
	}

	// --progress-file 必须放在子命令之前（argparse 主解析器参数）
	full := append([]string{python, script, "--progress-file", progressPath}, argv...)
	c := r.Command(full[0], full[1:]...)
	c.Dir = r.repoRoot
	c.Env = append(os.Environ(), "PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	logFile, err := os.Create(logPath) // stdout/stderr 原样落盘，不解析
	if err != nil {
		return err
	}
	c.Stdout = logFile
	c.Stderr = logFile

	r.mu.Lock()
	if _, dup := r.procs[id]; dup {
		r.mu.Unlock()
		logFile.Close()
		return fmt.Errorf("任务已在运行: %s", id)
	}
	// created 窗口/竞态：hStop 可能抢在注册进程前到达（Stop 对无进程任务
	// 也插 stopping 旗），此处自检放弃，不得照常起进程把停止吞掉。
	if r.stopping[id] {
		delete(r.stopping, id)
		r.mu.Unlock()
		logFile.Close()
		return fmt.Errorf("任务已请求停止: %s", id)
	}
	if err := c.Start(); err != nil {
		r.mu.Unlock()
		logFile.Close()
		return fmt.Errorf("启动失败: %w", err)
	}
	r.procs[id] = c
	delete(r.stopping, id)
	r.mu.Unlock()

	// P2（对抗实锤）：进程挂进「随壳消亡」的 Job Object——壳被硬杀时
	// 句柄随进程回收而关闭，KILL_ON_JOB_CLOSE 让扫描进程树同步终局，
	// 不再留孤儿扫描。挂载失败不阻断起扫描（killTree 兜底仍在）。
	if job, jerr := attachJob(c.Process.Pid); jerr == nil {
		r.setJob(id, job)
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
		logFile.Close()
	}()
	r.sinkOrDefault().SetStatus(id, store.StatusRunning, nil)
	go r.monitor(id, c, progressPath, done)
	return nil
}

// monitor 周期拉进度；进程退出后补收尾事件并落终态。
func (r *Runner) monitor(id string, c *exec.Cmd, progressPath string, done <-chan error) {
	sink := r.sinkOrDefault()
	tailer := NewTailer(progressPath)
	sawEnd := false
	endDetail := ""
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	var exitErr error
	finished := false
	for !finished {
		select {
		case exitErr = <-done:
			finished = true
		case <-ticker.C:
		}
		if evs := tailer.Poll(); len(evs) > 0 {
			for _, ev := range evs {
				if ev.Event == "pipeline_end" {
					sawEnd = true
					endDetail = ev.Detail
				}
			}
			sink.AppendProgress(id, evs)
		}
	}

	r.mu.Lock()
	delete(r.procs, id)
	r.mu.Unlock()
	r.clearJob(id) // 进程已退出，收掉 Job 句柄（对已退出进程无害）

	// 兜底：进程没了却没等到 pipeline_end（崩溃/被外部杀）→ 补一条 fail 收尾
	if !sawEnd {
		sink.AppendProgress(id, []store.ProgressEvent{{
			Ts: float64(time.Now().UnixMilli()) / 1e3, Module: "pipeline",
			Event: "pipeline_end", Detail: "fail",
		}})
	}

	r.mu.Lock()
	wasStopping := r.stopping[id]
	delete(r.stopping, id)
	r.mu.Unlock()

	exitCode := 0
	if exitErr != nil {
		var ee *exec.ExitError
		if errors.As(exitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	switch {
	case wasStopping:
		sink.SetStatus(id, store.StatusStopped, &exitCode)
	case exitErr == nil && sawEnd && endDetail == "done":
		sink.SetStatus(id, store.StatusDone, &exitCode)
	default:
		sink.SetStatus(id, store.StatusFail, &exitCode)
	}
}

// Stop 终止进程树（Windows：taskkill /T /F；其他平台 Kill）。
func (r *Runner) Stop(id string) error {
	r.mu.Lock()
	c, ok := r.procs[id]
	// 无进程也插旗：并发在途的 Start（尚未注册进程）自检后放弃，
	// 否则 hStop 已落 stopped 而 Start 照常把任务跑完。
	r.stopping[id] = true
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotRunning, id)
	}
	err := killTree(c)
	// 树杀后收掉 Job 句柄（对已退出进程无害；killTree 若失败，
	// KILL_ON_JOB_CLOSE 仍让整树在句柄关闭时终局）。
	r.clearJob(id)
	return err
}

// StopAll 收尾用：杀掉全部运行中的进程树，并收掉全部 Job 句柄。
func (r *Runner) StopAll() {
	r.mu.Lock()
	procs := make([]*exec.Cmd, 0, len(r.procs))
	jobs := make([]io.Closer, 0, len(r.jobs))
	for id, c := range r.procs {
		r.stopping[id] = true
		procs = append(procs, c)
	}
	for id, j := range r.jobs {
		jobs = append(jobs, j)
		delete(r.jobs, id)
	}
	r.mu.Unlock()
	for _, c := range procs {
		_ = killTree(c)
	}
	for _, j := range jobs {
		_ = j.Close() // KILL_ON_JOB_CLOSE：句柄关闭即整树终局
	}
}

// setJob 登记任务的 Job 句柄（调用方持锁与否不限，内部自锁）。
func (r *Runner) setJob(id string, j io.Closer) {
	if j == nil {
		return
	}
	r.mu.Lock()
	r.jobs[id] = j
	r.mu.Unlock()
}

// clearJob 收掉并注销任务的 Job 句柄（幂等；句柄缺失为无操作）。
func (r *Runner) clearJob(id string) {
	r.mu.Lock()
	j, ok := r.jobs[id]
	delete(r.jobs, id)
	r.mu.Unlock()
	if ok && j != nil {
		_ = j.Close()
	}
}

// RunningIDs 运行中的任务 ID。
func (r *Runner) RunningIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.procs))
	for id := range r.procs {
		out = append(out, id)
	}
	return out
}

// IsRunning 任务是否仍在运行。
func (r *Runner) IsRunning(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.procs[id]
	return ok
}

func killTree(c *exec.Cmd) error {
	if c.Process == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		// 先树杀（连带 python 起的子进程），失败再退回直接 Kill
		if err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(c.Process.Pid)).Run(); err == nil {
			return nil
		}
	}
	// 进程已自行退出（并发双停/竞态）按幂等成功处理，不让调用方报"停止失败"。
	// Windows 对已退出进程可能回 ErrProcessDone，也可能回 EINVAL（句柄已失效）。
	if err := c.Process.Kill(); err != nil {
		if errors.Is(err, os.ErrProcessDone) || strings.Contains(err.Error(), "invalid argument") {
			return nil
		}
		return err
	}
	return nil
}
