// Package engine：桌面进程内直调执行器。第 2 步（直调重写）后本包不再
// 起任何扫描子进程——八模块逐一映射 engine-go 公开函数（子进程壳、
// taskkill 树杀、Job Object、进度 JSONL Tailer、ResolvePython/ResolveGoEngine
// 均随第二步整体退役）。进度事件即 store.ProgressEvent，经 Sink 直达任务库
// 内存切片；Stop = context 取消，取消沿引擎 RunContext→FetchOpt.Ctx 贯穿。
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/apiunauth"
	"github.com/Kur1sulab/src-recon-tool/engine-go/baseline"
	"github.com/Kur1sulab/src-recon-tool/engine-go/cli"
	"github.com/Kur1sulab/src-recon-tool/engine-go/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/paths"
	"github.com/Kur1sulab/src-recon-tool/engine-go/reverseip"
	"github.com/Kur1sulab/src-recon-tool/engine-go/subdomain"

	"recon-native/internal/store"
	"recon-native/internal/whitelist"
)

// cmdSet 允许下发的模块白名单（八模块）。jsintel/portscan 随全集成退役
// （engine-go 未移植该两模块，桌面 all 流程里对应步骤发 skipped 事件）；
// 历史任务照常展示（ui.moduleLabel 保留退役模块中文映射）。
var cmdSet = map[string]bool{
	"all": true, "paths": true, "api": true, "fingerprint": true,
	"subdomain": true, "reverse": true, "icp": true, "baseline": true,
}

// Sink 引擎向任务库回写状态/进度的通道（session 侧实现，测试侧用假件）。
type Sink interface {
	AppendProgress(taskID string, evs []store.ProgressEvent)
	SetStatus(taskID, status string, exitCode *int)
}

// ModuleFunc 单模块执行函数（进程内直调的模块表注入接缝）：生产用内置实现，
// 测试注入桩函数测事件序列/终态/Stop 幂等/取消竞态。实现收到与 Start 相同的
// 归一化 target 与 extra；返回错误 = 模块失败（fail 事件 + 终态 fail）。
type ModuleFunc func(ctx context.Context, id, target string, extra []string) error

// inprocJob 一个运行中任务的进程内作业句柄。
type inprocJob struct {
	cancel context.CancelFunc
	done   chan struct{} // job goroutine 收尾完成时关闭（同步点）
	cmd    string
}

// Runner 管理全部运行中的扫描任务（进程内直调，零子进程）。
type Runner struct {
	mu       sync.Mutex
	repoRoot string // 扫描产物 out/ 的落点根（与引擎/Python 三方同名规则）
	jobs     map[string]*inprocJob
	stopping map[string]bool
	sink     Sink

	// 模块函数表：cmd → 执行函数。生产在 NewRunner 装配内置实现；
	// SetModuleFunc 为测试接缝。
	modules map[string]ModuleFunc

	// pickBase 接缝：baseline 的 HTTP 类检查入口推导（生产 = cli.PickBase，
	// 与 engine-go cli.go baseline 分支同参；测试注入本地靶站地址）。
	pickBase func(host string) string
}

// NewRunner 组装直调 runner：repoRoot=仓库根（扫描产物 out/ 落点）。
func NewRunner(repoRoot string) *Runner {
	r := &Runner{
		repoRoot: repoRoot,
		jobs:     make(map[string]*inprocJob),
		stopping: make(map[string]bool),
		pickBase: cli.PickBase,
	}
	r.modules = map[string]ModuleFunc{
		"all":         r.runAllModule,
		"subdomain":   r.runSubdomain,
		"paths":       r.runPaths,
		"api":         r.runAPI,
		"fingerprint": r.runFingerprint,
		"reverse":     r.runReverse,
		"icp":         r.runICP,
		"baseline":    r.runBaseline,
	}
	return r
}

// SetSink 注入状态回写通道（并发纪律：与 sinkOrDefault 同锁，运行中调用
// 不再是并发读写；语义上仍建议在 Start 之前装配）。
func (r *Runner) SetSink(s Sink) {
	r.mu.Lock()
	r.sink = s
	r.mu.Unlock()
}

// SetModuleFunc 注入/替换模块执行函数（测试接缝；cmd 不在白名单内为无操作）。
func (r *Runner) SetModuleFunc(cmd string, fn ModuleFunc) {
	if !cmdSet[cmd] {
		return
	}
	r.mu.Lock()
	r.modules[cmd] = fn
	r.mu.Unlock()
}

func (r *Runner) sinkOrDefault() Sink {
	r.mu.Lock()
	s := r.sink
	r.mu.Unlock()
	if s == nil {
		return nopSink{}
	}
	return s
}

type nopSink struct{}

func (nopSink) AppendProgress(string, []store.ProgressEvent) {}
func (nopSink) SetStatus(string, string, *int)               {}

// ErrNotRunning 任务不在运行（作业表无此 ID）。调用方（如 session 的 stop）
// 应按幂等成功处理：任务已自然收尾或尚未起步。
var ErrNotRunning = errors.New("任务未在运行")

// CmdAllowed 报告子命令是否在八模块白名单内。
func CmdAllowed(cmd string) bool { return cmdSet[cmd] }

// taskIDRe 任务 id 形态：字母数字开头结尾，中间允许点/连字符/下划线，
// 全长 ≤80——id 会出现在日志与任务库键里，畸形 id 在引擎层就地拒绝。
var taskIDRe = regexp.MustCompile(`^[0-9A-Za-z]([0-9A-Za-z._-]{0,78}[0-9A-Za-z])?$`)

// Start 起一个进程内扫描作业。成功后任务状态置 running。
func (r *Runner) Start(id, cmd, target string, extra []string) error {
	// 引擎层纵深闸（fix3 原样平移）：正常流程里调用方（session.CreateTask）
	// 已过目标格式校验与参数闸，但本层不信任该前提——未来任何新调用方直连
	// Start，也不至于把格式非法的目标送进扫描。目标本身全部默认授权
	//（用户裁定 2026-10-05），本闸只做格式卫生。
	if _, err := whitelist.Check(target); err != nil {
		return fmt.Errorf("目标格式校验未通过：%w", err)
	}
	if !taskIDRe.MatchString(id) {
		return fmt.Errorf("任务 ID 含不允许的字符：%q", id)
	}
	if !cmdSet[cmd] {
		return fmt.Errorf("不支持的子命令：%s", cmd)
	}
	if err := ValidateExtraArgs(cmd, extra); err != nil {
		return err
	}

	r.mu.Lock()
	if _, dup := r.jobs[id]; dup {
		r.mu.Unlock()
		return fmt.Errorf("任务已在运行：%s", id)
	}
	// created 窗口/竞态：Stop 可能抢在注册作业前到达（Stop 对无作业任务
	// 也插 stopping 旗），此处自检放弃，不得照常执行把停止吞掉
	//（语义自旧 runner.go:317-323 平移）。
	if r.stopping[id] {
		delete(r.stopping, id)
		r.mu.Unlock()
		return fmt.Errorf("任务已请求停止：%s", id)
	}
	job := &inprocJob{done: make(chan struct{}), cmd: cmd}
	ctx, cancel := context.WithCancel(context.Background())
	job.cancel = cancel
	r.jobs[id] = job
	delete(r.stopping, id)
	r.mu.Unlock()

	r.sinkOrDefault().SetStatus(id, store.StatusRunning, nil)
	go func() {
		err := r.execTask(ctx, id, cmd, target, extra)
		// 取消态必须先于 cancel() 采样——cancel 在此处只是释放 ctx 资源，
		// 采样放在它后面会把每个自然完成的任务都误判成 stopped。
		cancelled := ctx.Err() != nil
		cancel() // 引擎返回后释放 ctx 资源（幂等）
		r.mu.Lock()
		delete(r.jobs, id)
		wasStopping := r.stopping[id]
		delete(r.stopping, id)
		r.mu.Unlock()
		close(job.done)

		// 终态裁决：取消（含停止旗）→ stopped；引擎报错 → fail；否则 done。
		// 与旧 monitor 终态机同语义（exitCode 概念随子进程退役，恒 0/1）。
		switch {
		case wasStopping || cancelled:
			code := 0
			r.sinkOrDefault().SetStatus(id, store.StatusStopped, &code)
		case err != nil:
			code := 1
			r.sinkOrDefault().SetStatus(id, store.StatusFail, &code)
		default:
			code := 0
			r.sinkOrDefault().SetStatus(id, store.StatusDone, &code)
		}
	}()
	return nil
}

// execTask 单任务调度：发 pipeline_start → start(cmd) → 模块执行（含引擎
// 内层事件）→ done|fail(cmd) → pipeline_end(done|fail)。all 无模块级
// start/done（recon.py:250-256 / cli.go:98 契约），步骤级事件由 allrunner 发。
func (r *Runner) execTask(ctx context.Context, id, cmd, target string, extra []string) error {
	r.emit(id, "pipeline", "pipeline_start", cmd)
	if cmd != "all" {
		r.emit(id, cmd, "start", "")
	}
	err := r.runModule(ctx, id, cmd, target, extra)
	switch {
	case ctx.Err() != nil:
		// 停止/取消：补流水线收尾事件（旧壳兜底同款 fail 语义），终态由
		// job goroutine 判 ctx 落 stopped。
		r.emit(id, "pipeline", "pipeline_end", "fail")
		return err
	case err != nil:
		if cmd != "all" {
			r.emit(id, cmd, "fail", err.Error())
		}
		r.emit(id, "pipeline", "pipeline_end", "fail")
		return err
	default:
		if cmd != "all" {
			r.emit(id, cmd, "done", "")
		}
		r.emit(id, "pipeline", "pipeline_end", "done")
		return nil
	}
}

// runModule 取模块函数执行（终修轮两件事并一处）：
//  1. 并发纪律（审计 low#4）：modules 表读与 SetModuleFunc 写共用 r.mu——
//     此前 job goroutine 无锁读 map，运行中调用导出接缝即并发 map 读写
//     → runtime fatal（不可 recover 的整进程死）。
//  2. panic 兜底（审计 high#1）：直调重写后八模块全跑在本桌面进程的
//     job goroutine 上，任一引擎代码 panic（敌意远端数据解析路径：JSON
//     类型断言/切片越界/TLS 解析）即炸穿整个 exe、所有任务同灭。一处
//     recover 就地把 panic 转 error → 走既有 fail 事件/终态机，只死本任务。
//     all 模块的 allStep fn() 直调在本函数调用树内，同一兜底面覆盖。
func (r *Runner) runModule(ctx context.Context, id, cmd, target string, extra []string) (err error) {
	r.mu.Lock()
	fn := r.modules[cmd]
	r.mu.Unlock()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("引擎内部异常（panic 已兜底，仅失败本任务）：%v", p)
		}
	}()
	return fn(ctx, id, target, extra)
}

// emit 追加一条进度事件（即 store.ProgressEvent 契约：ts/module/event/detail）。
func (r *Runner) emit(id, module, event, detail string) {
	r.sinkOrDefault().AppendProgress(id, []store.ProgressEvent{{
		Ts:     float64(time.Now().UnixMilli()) / 1e3,
		Module: module,
		Event:  event,
		Detail: detail,
	}})
}

// makeOutDir 产物目录：repoRoot/out/<目标清洗名>，目录名与 Python make_outdir /
// engine-go MakeOutdir 三方同名契约一致（cli.OutdirName 同一实现）。
func (r *Runner) makeOutDir(target string) (string, error) {
	out := filepath.Join(r.repoRoot, "out", cli.OutdirName(target))
	if err := os.MkdirAll(out, 0o755); err != nil {
		return out, err
	}
	return out, nil
}

// Stop 停止任务：cancel 作业 ctx，取消沿引擎 RunContext 贯穿（FetchOpt.Ctx、
// 循环检查点、toolrun CommandContext）。直调后桌面进程内无壳启动的子进程，
// 无进程树可级联（原 taskkill/Job Object 路径整体退役）。
func (r *Runner) Stop(id string) error {
	r.mu.Lock()
	job, ok := r.jobs[id]
	// 无作业也插旗：并发在途的 Start（尚未注册）自检后放弃，
	// 否则停止已确认而 Start 照常把任务跑完。
	r.stopping[id] = true
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotRunning, id)
	}
	job.cancel() // 幂等：context 取消可重入，双停/停后查无副作用
	return nil
}

// StopAll 收尾用：取消全部运行中的作业（关窗路径）。
func (r *Runner) StopAll() {
	r.mu.Lock()
	jobs := make([]*inprocJob, 0, len(r.jobs))
	for id, j := range r.jobs {
		r.stopping[id] = true
		jobs = append(jobs, j)
	}
	r.mu.Unlock()
	for _, j := range jobs {
		j.cancel()
	}
}

// RunningIDs 运行中的任务 ID。
func (r *Runner) RunningIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.jobs))
	for id := range r.jobs {
		out = append(out, id)
	}
	return out
}

// IsRunning 任务是否仍在运行。
func (r *Runner) IsRunning(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.jobs[id]
	return ok
}

// ── 单模块直调实现（任务模型映射表；out 目录规则见 makeOutDir）──

// runSubdomain 子域枚举；extra 含 --verify 时续跑存活验证（out,8,true，与
// engine-go cli.go subdomain 分支同参）。
func (r *Runner) runSubdomain(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	if _, err := subdomain.RunContext(ctx, target, out); err != nil {
		return err
	}
	if extraHasFlag(extra, "--verify") {
		subdomain.RunVerifyContext(ctx, out, 8, true)
	}
	return nil
}

func (r *Runner) runPaths(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	_, err = paths.RunPathsContext(ctx, target, out)
	return err
}

func (r *Runner) runAPI(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	_, err = apiunauth.RunAPIContext(ctx, target, out, true) // 取证模式，与 cli.go:272 同参
	return err
}

func (r *Runner) runFingerprint(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	fingerprint.RunFingerprintContext(ctx, target, out)
	return nil
}

func (r *Runner) runReverse(ctx context.Context, id, target string, extra []string) error {
	// IP 形态闸保留（cli.go:219 同款 fail-closed；session 层已有同规则前置）
	if net.ParseIP(target) == nil {
		return fmt.Errorf("非法 IP: %q（reverse 需要合法 IPv4/IPv6 地址）", target)
	}
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	reverseip.RunReverseContext(ctx, target, out)
	return nil
}

func (r *Runner) runICP(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	icp.RunICPContext(ctx, target, out)
	return nil
}

// runBaseline 基线检查：与 engine-go cli.go:385-393 同参直调 baseline。
// URL 经 pickBase 接缝推导（生产 = cli.PickBase）；逐检查 start/done/fail/
// skipped 事件经 Options.Emit 直通 sink；Logf 静默（桌面进程内无控制台管道）。
// 超时沿用引擎默认（PerCheckTimeout 60s / TotalBudget 5min），壳级不加总超时。
func (r *Runner) runBaseline(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	opts, err := buildBaselineOptions(target, extra, out)
	if err != nil {
		return err
	}
	opts.URL = r.pickBase(target)
	opts.Emit = func(event, module, detail string) { r.emit(id, module, event, detail) }
	return baseline.RunContext(ctx, opts)
}

// buildBaselineOptions 组装 baseline.Options（URL/Emit 由调用方补齐）：
// --checks 归一化（缺省展开全 8 项；未知检查名就地拒绝，零网络副作用），
// AllowPrivate 恒开。
func buildBaselineOptions(domain string, extra []string, out string) (baseline.Options, error) {
	var raw []string
	if v, ok := extraFlagValue(extra, "--checks"); ok && strings.TrimSpace(v) != "" {
		raw = strings.Split(v, ",")
	}
	checks, err := baseline.NormalizeChecks(raw)
	if err != nil {
		return baseline.Options{}, err
	}
	return baseline.Options{
		Domain:       domain,
		Out:          out,
		Checks:       checks,
		AllowPrivate: true, // 桌面契约：授权内网目标放行（cli.go:387 同参）
	}, nil
}

// extraHasFlag extra 里是否出现布尔旗标（--verify / --verify=true 均算）。
func extraHasFlag(extra []string, name string) bool {
	for _, tk := range extra {
		if tk == name || strings.HasPrefix(tk, name+"=") {
			return true
		}
	}
	return false
}

// extraFlagValue 取值旗标的值：支持 "--name value" 与 "--name=value" 两形态；
// 出现多次取最后一个（与 argparse last-wins 一致）。未出现返回 (""，false)。
func extraFlagValue(extra []string, name string) (string, bool) {
	found, val := false, ""
	for i := 0; i < len(extra); i++ {
		tk := extra[i]
		if tk == name {
			if i+1 < len(extra) {
				val = extra[i+1]
				found = true
			}
			continue
		}
		if strings.HasPrefix(tk, name+"=") {
			val = strings.TrimPrefix(tk, name+"=")
			found = true
		}
	}
	return val, found
}
