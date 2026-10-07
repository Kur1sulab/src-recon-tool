package engine

// adv_inproc_integration_test.go — 集成轮对抗（进程内直调执行器当靶子真打）。
// 零外网零子进程零 GUI：httptest 本地靶站（127.0.0.1）+ 包内注入桩 + 真实
// store 落盘。五路攻击面：
//
//  1. 并发 Start/Stop 同任务：口径结算（每个 Start 结果必属三类之一）+
//     停止旗消费后同 ID 可恢复（stopFlagOnlyGod — 见 fix2b 语义）；
//  2. Stop 后引擎 goroutine 真退：桩观察 ctx.Err()==Canceled + NumGoroutine
//     回落基线；真引擎在飞 HTTP 被取消（服务端 r.Context() 感知断连 = ctx
//     贯穿到传输层实证）；baseline 检查级 60s 超时被取消抢占；
//  3. 恶意目标串直灌直调函数：控制字符/超长/明文与编码穿越/UNC/盘符等在
//     Start 闸就地拒绝且零副作用（无作业/无状态/无事件/无产物目录）；绕过
//     Start 闸直调 makeOutDir 时产物路径必须锁死在 repoRoot 之内；
//  4. 进度事件洪水：真 store 落盘 + 失控发射器 + 并发读手 + 中途 Stop——
//     计数封顶 MaxProgress、tasks.json 保持合法 JSON、取消不被 sink 阻塞；
//     附写放大/单条体积实测数据（修复建议素材，不作断言）；
//  5. 多任务并发互扰：3 真模块任务并发（含同目标任务共享产物目录的钉子）
//     + 1 慢任务中途停——完成者不受牵连、事件流水不串线、产物目录各归各。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/cli"
	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"

	"recon-native/internal/store"
)

// ── 集成轮假件 ──

// advHistSink 原样记录全部 SetStatus 流水（不做终态兜底——「终态不回退」是
// ui.sessionSink 的职责，本包测试要看引擎层裸语义，见 TestAdvIntStartStopHammer）。
type advHistSink struct {
	mu      sync.Mutex
	events  map[string][]store.ProgressEvent
	status  map[string]string
	history []string // "id=status" 原样流水
}

func newAdvHistSink() *advHistSink {
	return &advHistSink{events: map[string][]store.ProgressEvent{}, status: map[string]string{}}
}

func (f *advHistSink) AppendProgress(id string, evs []store.ProgressEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[id] = append(f.events[id], evs...)
}

func (f *advHistSink) SetStatus(id, status string, _ *int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = status
	f.history = append(f.history, id+"="+status)
}

func (f *advHistSink) statusOf(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id]
}

func (f *advHistSink) eventsOf(id string) []store.ProgressEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.ProgressEvent(nil), f.events[id]...)
}

func (f *advHistSink) historyOf(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, h := range f.history {
		if strings.HasPrefix(h, id+"=") {
			out = append(out, h)
		}
	}
	return out
}

// advDiskSink 与 ui.sessionSink 同构（engine 包测试 import ui 会成环，按生产
// 实现同语义复制：终态不回退）。给「真 store 落盘」的洪水/互扰用例当 sink。
type advDiskSink struct{ st *store.Store }

func (s advDiskSink) AppendProgress(id string, evs []store.ProgressEvent) { s.st.AppendProgress(id, evs) }

func (s advDiskSink) SetStatus(id, status string, code *int) {
	_ = s.st.Update(id, func(t *store.Task) {
		switch t.Status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			return
		}
		t.Status = status
		t.ExitCode = code
	})
}

// advSlowServer 慢响应靶站：每请求睡 slow 后回 200；客户端中途取消时经
// r.Context().Done() 即刻返回并计入 cancels——这是「ctx 贯穿到 HTTP 传输层」
// 的服务端探针（客户端断连 ⇒ 服务端请求上下文取消）。
type advSlowServer struct {
	srv      *httptest.Server
	total    atomic.Int64
	inflight atomic.Int64
	cancels  atomic.Int64
}

func newAdvSlowServer(t *testing.T, slow time.Duration) *advSlowServer {
	t.Helper()
	s := &advSlowServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.total.Add(1)
		s.inflight.Add(1)
		defer s.inflight.Add(-1)
		select {
		case <-time.After(slow):
		case <-r.Context().Done():
			s.cancels.Add(1)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// advWaitCond 轮询等待条件成立（集成用例统一出口，超时即 Fatal）。
func advWaitCond(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时（%s）：%s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// advWaitGoroutinesBack 等 goroutine 数回落到基线 +2 且连续 3 次采样稳定。
func advWaitGoroutinesBack(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		if n := runtime.NumGoroutine(); n <= baseline+2 {
			stable++
			if stable >= 3 {
				return
			}
		} else {
			stable = 0
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("goroutine 未回落到基线：基线 %d，当前 %d", baseline, runtime.NumGoroutine())
}

func advDirNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// ── 1. 并发 Start/Stop 同任务 ──

// TestAdvIntStartStopHammerAccounting Start/Stop 对打的口径结算：每个 Start
// 的结果必须恰属「成功 / 已在运行 / 已请求停止」三类之一；收尾后作业表清空、
// 裸状态不停 running；且停止旗消费后同 ID 必须可重新起步跑到 done（旗自清理，
// 生产 genID 不复用 ID，此处钉的是引擎层旗语义不留死局）。
func TestAdvIntStartStopHammerAccounting(t *testing.T) {
	// 手工装配（newTestRunner 的 fakeSink 无流水记录；此处要看裸 SetStatus 序）
	r := NewRunner(t.TempDir())
	sink := newAdvHistSink()
	r.SetSink(sink)
	for _, c := range []string{"all", "paths", "api", "fingerprint", "subdomain", "reverse", "icp", "baseline"} {
		r.SetModuleFunc(c, blockUntilCancel)
	}
	id := "adv-int-hammer"

	var mu sync.Mutex
	var ok, dup, abort, other int
	var otherErrs []string
	deadline := time.Now().Add(1500 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // 打手 A：反复起
		defer wg.Done()
		for time.Now().Before(deadline) {
			err := r.Start(id, "icp", "xycovo.com", nil)
			mu.Lock()
			switch {
			case err == nil:
				ok++
			case strings.Contains(err.Error(), "已在运行"):
				dup++
			case strings.Contains(err.Error(), "已请求停止"):
				abort++
			default:
				other++
				otherErrs = append(otherErrs, err.Error())
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}()
	go func() { // 打手 B：反复停
		defer wg.Done()
		for time.Now().Before(deadline) {
			_ = r.Stop(id)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	wg.Wait()

	// 收尾：终停一次 + 作业表清空
	_ = r.Stop(id)
	waitGone(t, r, id)
	if other > 0 {
		t.Fatalf("Start 出现口径外错误 %d 次: %v", other, otherErrs)
	}
	for _, h := range sink.historyOf(id) {
		st := strings.TrimPrefix(h, id+"=")
		switch st {
		case store.StatusRunning, store.StatusDone, store.StatusFail, store.StatusStopped:
		default:
			t.Fatalf("口径外状态流转: %s", h)
		}
	}
	if last := sink.statusOf(id); last == store.StatusRunning {
		t.Fatal("收尾后裸状态不得停留 running")
	}
	t.Logf("Start/Stop 对打 1.5s 结算：成功 %d / 已在运行 %d / 已请求停止 %d", ok, dup, abort)

	// 同 ID 重启：停止旗应在「自检放弃」或「作业收尾」两路之一被消费，
	// 3 次尝试内必须能重新起步并跑到 done——否则停止旗就是死局。
	r.SetModuleFunc("icp", func(context.Context, string, string, []string) error { return nil })
	launched := false
	for i := 0; i < 3 && !launched; i++ {
		err := r.Start(id, "icp", "xycovo.com", nil)
		if err == nil {
			launched = true
			break
		}
		if !strings.Contains(err.Error(), "已请求停止") {
			t.Fatalf("重启得到口径外错误: %v", err)
		}
	}
	if !launched {
		t.Fatal("收尾后同 ID 重启 3 次内应成功（停止旗应被消费，不得死局）")
	}
	advWaitCond(t, 8*time.Second, "重启任务应落 done（等待期旧终态 stopped 不算）",
		func() bool { return sink.statusOf(id) == store.StatusDone })
}

// ── 2. Stop 后引擎 goroutine 真退（ctx 贯穿）──

// TestAdvIntStopGoroutineTrulyExits 桩级实证：模块在取消后苏醒并观察到
// context.Canceled；终态 stopped、作业出表、进程 goroutine 数回落基线。
func TestAdvIntStopGoroutineTrulyExits(t *testing.T) {
	r, sink := newTestRunner(t)
	runtime.Gosched()
	baseline := runtime.NumGoroutine()

	entered := make(chan struct{})
	errCh := make(chan error, 1)
	r.SetModuleFunc("subdomain", func(ctx context.Context, _, _ string, _ []string) error {
		close(entered)
		<-ctx.Done()
		errCh <- ctx.Err()
		time.Sleep(80 * time.Millisecond) // 模拟收尾清理耗时
		return ctx.Err()
	})
	if err := r.Start("adv-exit", "subdomain", "xycovo.com", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-entered
	if err := r.Stop("adv-exit"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if st := waitTerminal(t, sink, "adv-exit"); st != store.StatusStopped {
		t.Fatalf("应落 stopped，得 %q", st)
	}
	waitGone(t, r, "adv-exit")
	select {
	case v := <-errCh:
		if !errors.Is(v, context.Canceled) {
			t.Fatalf("模块桩应观察到 context.Canceled，得 %v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("模块桩未在取消后 5s 内苏醒退出")
	}
	advWaitGoroutinesBack(t, baseline)
}

// TestAdvIntStopCancelsInFlightPathsScan 真引擎实证（paths 模块 vs 慢靶站）：
// 中途 Stop 后 ①终态远早于全量扫描时长落地 ②在飞 HTTP 请求被断连中止
//（服务端感知客户端取消 = ctx 贯穿传输层）③取消后请求流水冻结。
func TestAdvIntStopCancelsInFlightPathsScan(t *testing.T) {
	slow := newAdvSlowServer(t, 1200*time.Millisecond) // 全量 21 项 ≈ 25s，取消必须远早于此
	repo := t.TempDir()
	r := NewRunner(repo)
	sink := newFakeSink()
	r.SetSink(sink)
	if err := r.Start("adv-paths", "paths", slow.srv.URL, nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// 贴身盯梢（3ms 粒度）：确认扫描已进入逐项探测且至少一条请求在飞时立刻停
	deadline := time.Now().Add(15 * time.Second)
	for !(slow.total.Load() >= 2 && slow.inflight.Load() >= 1) {
		if time.Now().After(deadline) {
			t.Fatal("慢靶站应收到扫描请求（基线探测 + 字典项）")
		}
		time.Sleep(3 * time.Millisecond)
	}
	t0 := time.Now()
	if err := r.Stop("adv-paths"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	advWaitCond(t, 6*time.Second, "取消后任务应远早于全量扫描时长（≈25s）落终态", func() bool {
		st := sink.statusOf("adv-paths")
		return st == store.StatusStopped || st == store.StatusDone || st == store.StatusFail
	})
	if st := sink.statusOf("adv-paths"); st != store.StatusStopped {
		t.Fatalf("取消任务应落 stopped，得 %q（耗时 %s）", st, time.Since(t0))
	}
	t.Logf("paths 取消收尾耗时 %s（全量 ≈25s，检查级无超时可依——纯靠 ctx 贯穿）", time.Since(t0))
	// 服务端感知客户端断连：ctx 到了传输层
	advWaitCond(t, 2*time.Second, "在飞请求应清零", func() bool { return slow.inflight.Load() == 0 })
	if slow.cancels.Load() < 1 {
		t.Fatal("服务端应观察到至少一次客户端取消（ctx 未贯穿 HTTP 层）")
	}
	// 取消后不得再发新请求（至多补完取消瞬间已发出的最后一条）
	s1 := slow.total.Load()
	time.Sleep(1200 * time.Millisecond)
	if d := slow.total.Load() - s1; d > 1 {
		t.Fatalf("取消后扫描应停止发请求，1.2s 内新增 %d 条", d)
	}
}

// TestAdvIntStopPreemptsBaselineCheckTimeout 真引擎实证（baseline 模块）：
// 检查级超时默认 60s、靶站挂 30s——中途 Stop 必须经 ctx 抢占检查（而不是等
// 超时），服务端同样感知客户端断连。
func TestAdvIntStopPreemptsBaselineCheckTimeout(t *testing.T) {
	slow := newAdvSlowServer(t, 30*time.Second) // 远小于 60s 检查级超时也远大于测试耐心
	repo := t.TempDir()
	r := NewRunner(repo)
	r.pickBase = func(string) string { return slow.srv.URL } // PickBase 接缝注入本地靶站
	sink := newFakeSink()
	r.SetSink(sink)
	if err := r.Start("adv-base", "baseline", "secbaseline.invalid", []string{"--checks", "secheaders"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	advWaitCond(t, 15*time.Second, "secheaders 应已发出请求", func() bool { return slow.total.Load() >= 1 })
	t0 := time.Now()
	if err := r.Stop("adv-base"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	advWaitCond(t, 8*time.Second, "取消应抢占检查（不等 60s 超时）落 stopped", func() bool {
		return sink.statusOf("adv-base") == store.StatusStopped
	})
	t.Logf("baseline 取消收尾耗时 %s（检查级超时 60s、处理器睡 30s——取消即抢占）", time.Since(t0))
	advWaitCond(t, 2*time.Second, "在飞请求应清零", func() bool { return slow.inflight.Load() == 0 })
	if slow.cancels.Load() < 1 {
		t.Fatal("baseline 检查的 HTTP 层应观察到客户端取消（ctx 贯穿）")
	}
}

// ── 3. 恶意目标串直灌直调函数 ──

// TestAdvIntHostileTargetsZeroSideEffect 恶意目标/畸形 id 直灌 Start：全部
// 就地拒绝，且拒绝路径零副作用——无作业、无状态写入、无事件、无产物目录。
func TestAdvIntHostileTargetsZeroSideEffect(t *testing.T) {
	repo := t.TempDir()
	r := NewRunner(repo)
	sink := newAdvHistSink()
	r.SetSink(sink)

	// 恰 200 字符的合法长域名（63+1+63+1+63+1+8=200）：边界内应放行
	long200 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + ".abcdefgh"

	hostile := []struct{ name, target string }{
		{"NUL嵌入", "xycovo\x00.com"},
		{"换行注入", "xycovo.com\nevil.com"},
		{"回车注入", "xycovo.com\rSet-Cookie: 1"},
		{"ESC控制", "\x1b[31mxycovo.com"},
		{"DEL控制", "xycovo.com\x7f"},
		{"超长10KB", strings.Repeat("a", 10240)},
		{"明文穿越", "../../etc/passwd"},
		{"Windows穿越", "..\\..\\windows\\win.ini"},
		{"URL穿越", "http://xycovo.com/../../etc"},
		{"编码穿越", "http://xycovo.com/..%2f..%2fwin.ini"},
		{"UNC路径", "\\\\attacker\\share"},
		{"盘符路径", "C:\\Windows\\system32"},
		{"userinfo欺骗", "http://admin:pw@xycovo.com/"},
		{"全角混入", "ｘycovo.com"},
		{"RTLO欺骗", "xycovo\u202emoc."},
		{"端口超界", "xycovo.com:99999"},
		{"边界201", long200 + "x"},
	}
	for _, h := range hostile {
		if err := r.Start("adv-hostile", "icp", h.target, nil); err == nil {
			t.Fatalf("%s 目标 %q 应被引擎层拒绝", h.name, h.target)
		}
	}
	// 边界对照：恰 200 的合法域名放行（闸不过度），跑完收尾
	if err := r.Start("adv-edge200", "icp", long200, nil); err != nil {
		t.Fatalf("恰 200 字符合法域名应放行: %v", err)
	}
	_ = r.Stop("adv-edge200")
	waitGone(t, r, "adv-edge200")

	// 畸形任务 id 同样就地拒绝（id 曾进日志与库键）
	for _, bad := range []string{"../evil", "a\\b", "a b", "a\x00b", strings.Repeat("a", 81), ""} {
		if err := r.Start(bad, "icp", "xycovo.com", nil); err == nil {
			t.Fatalf("畸形任务 id %q 应拒绝", bad)
		}
	}

	// 零副作用四连：无作业 / 无状态 / 无事件；产物目录只允许边界对照组
	//（adv-edge200 放行后）留下的它自己那一个——恶意拒绝路径一个目录都不能留
	if ids := r.RunningIDs(); len(ids) != 0 {
		t.Fatalf("拒绝路径不得留下作业: %v", ids)
	}
	if st := sink.statusOf("adv-hostile"); st != "" {
		t.Fatalf("拒绝路径不得写状态，得 %q", st)
	}
	if evs := sink.eventsOf("adv-hostile"); len(evs) != 0 {
		t.Fatalf("拒绝路径不得发事件: %+v", evs)
	}
	outDir := filepath.Join(repo, "out")
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("产物根应存在（边界对照组建过目录）: %v", err)
	}
	wantEdge := cli.OutdirName(long200)
	if len(entries) != 1 || entries[0].Name() != wantEdge {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("产物目录应恰含边界对照组的 %q 一个，实际 %v（恶意拒绝路径不得留产物目录）", wantEdge, names)
	}
}

// TestAdvIntDirectMakeOutDirContainment 直调函数纵深（假设 Start 闸已被未来
// 调用方绕过）：makeOutDir 直灌穿越/UNC/保留设备名等恶意串，产物路径必须
// 锁死在 repoRoot 之内，仓库外一个字节都不能碰。
func TestAdvIntDirectMakeOutDirContainment(t *testing.T) {
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(repo)
	before := advDirNames(parent)

	oversize := strings.Repeat("z", 300) // Windows 路径长度上限，mkdir 必失败——只验 containment
	for _, hostile := range []string{
		"../escape1", "..\\..\\escape2", "....//....//escape3", "x/../../escape4",
		"..", ".", "", "con", "nul", "aux", "C:\\Windows", "a/b",
		"%2e%2e%2fescape5",
	} {
		got, err := r.makeOutDir(hostile)
		if err != nil {
			t.Fatalf("makeOutDir(%q) 不应出错（应清洗后落盘）: %v", hostile, err)
		}
		rel, relErr := filepath.Rel(repo, got)
		if relErr != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatalf("makeOutDir(%q) 越界: got=%q rel=%q", hostile, got, rel)
		}
	}
	if got, err := r.makeOutDir(oversize); err == nil {
		t.Logf("超长目录名在本机竟然创建成功: %q", got)
	} else if rel, relErr := filepath.Rel(repo, got); relErr != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("makeOutDir(超长) 越界: got=%q rel=%q", got, rel)
	}

	// 仓库外不得出现新条目（逃逸即写在 parent 层留下痕迹）
	after := advDirNames(parent)
	for _, n := range after {
		fresh := true
		for _, b := range before {
			if b == n {
				fresh = false
			}
		}
		if fresh && n != "repo" {
			t.Fatalf("目录逃逸：仓库外出现新条目 %q（全部=%v）", n, after)
		}
	}
}

// TestAdvIntDirectModuleGatesZeroNetwork 直调模块函数的形状闸：reverse 非 IP
// fail-closed 且零落盘；baseline 未知检查名就地拒绝且零网络（靶站计数 0）。
func TestAdvIntDirectModuleGatesZeroNetwork(t *testing.T) {
	repo := t.TempDir()
	r := NewRunner(repo)

	if err := r.runReverse(context.Background(), "adv-rev", "xycovo.com", nil); err == nil {
		t.Fatal("reverse 直调非 IP 目标应 fail-closed")
	}
	if _, err := os.Stat(filepath.Join(repo, "out")); !os.IsNotExist(err) {
		t.Fatal("reverse 拒绝路径不得建产物目录")
	}

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r.pickBase = func(string) string { return srv.URL }

	if err := r.runBaseline(context.Background(), "adv-base-bad", "secx.invalid",
		[]string{"--checks", "nonexistent"}); err == nil {
		t.Fatal("baseline 未知检查名应就地拒绝")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("未知检查名拒绝前不得发请求，实测 %d", n)
	}
}

// ── 4. 进度事件洪水 ──

// TestAdvIntProgressFloodCapStopAndReaders 失控发射器（模拟引擎内层 bug 级
// 洪水）直灌真 store：并发 UI 读手全程轮询、中途 Stop——断言计数封顶
// MaxProgress、tasks.json 始终是合法 JSON、取消不被 sink 阻塞、读手无死锁。
func TestAdvIntProgressFloodCapStopAndReaders(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "tasks.json"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	r := NewRunner(t.TempDir())
	r.SetSink(advDiskSink{st: st})

	now := float64(time.Now().UnixMilli()) / 1e3
	if err := st.Create(&store.Task{ID: "adv-flood", Target: "floodtest.invalid",
		Cmd: "icp", Status: store.StatusCreated, CreatedAt: now}); err != nil {
		t.Fatalf("入库: %v", err)
	}

	var batches atomic.Int64
	floodReturned := make(chan struct{})
	r.SetModuleFunc("icp", func(ctx context.Context, _, _ string, _ []string) error {
		defer close(floodReturned)
		batch := make([]store.ProgressEvent, 200)
		for i := range batch {
			batch[i] = store.ProgressEvent{Ts: now, Module: "icp", Event: "tick", Detail: strings.Repeat("x", 64)}
		}
		for {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			st.AppendProgress("adv-flood", batch) // 洪水：每批都触发一次全量落盘
			batches.Add(1)
			time.Sleep(20 * time.Millisecond) // 节流：避免用例本身灌爆磁盘，洪水语义不变
		}
	})

	// 并发读手：模拟 UI 轮询 List/Get 全程在场
	readDone := make(chan struct{})
	var readWG sync.WaitGroup
	readWG.Add(1)
	go func() {
		defer readWG.Done()
		for {
			select {
			case <-readDone:
				return
			default:
			}
			_ = st.List()
			_, _ = st.Get("adv-flood")
			time.Sleep(2 * time.Millisecond)
		}
	}()

	if err := r.Start("adv-flood", "icp", "floodtest.invalid", nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	advWaitCond(t, 5*time.Second, "洪水应起量", func() bool { return batches.Load() >= 5 })
	if err := r.Stop("adv-flood"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	advWaitCond(t, 3*time.Second, "洪水任务应快速落终态（sink 落盘不得阻塞取消）", func() bool {
		tk, ok := st.Get("adv-flood")
		return ok && (tk.Status == store.StatusStopped || tk.Status == store.StatusDone || tk.Status == store.StatusFail)
	})
	tk, _ := st.Get("adv-flood")
	if tk.Status != store.StatusStopped {
		t.Fatalf("取消的洪水任务应落 stopped，得 %q", tk.Status)
	}
	close(readDone)
	readWG.Wait()
	<-floodReturned

	// 计数封顶：无论灌了多少，UI 可见进度恒 ≤ MaxProgress
	t.Logf("洪水结算：发射 %d 批（%d 事件），UI 可见进度 %d 条（封顶 %d）",
		batches.Load(), batches.Load()*200, len(tk.Progress), store.MaxProgress)
	if len(tk.Progress) > store.MaxProgress {
		t.Fatalf("进度应封顶 %d，得 %d", store.MaxProgress, len(tk.Progress))
	}
	if len(tk.Progress) == 0 {
		t.Fatal("洪水任务进度不得为空")
	}
	// 落盘文件必须始终合法 JSON（saveLocked 原子性在洪水 + 并发读下保持）
	data, err := os.ReadFile(filepath.Join(dir, "tasks.json"))
	if err != nil {
		t.Fatalf("tasks.json 应可读: %v", err)
	}
	var tasks []store.Task
	if err := json.Unmarshal(data, &tasks); err != nil {
		t.Fatalf("洪水 + 并发读下 tasks.json 应保持合法 JSON: %v（%d 字节）", err, len(data))
	}
}

// TestAdvIntFloodMetricsForFixes 洪水维度实测（不做断言，产出修复建议素材）：
// 单批 10 万事件的计数封顶；单条 5MB detail 炸弹的落盘体积（计数封顶管不住
// 单条体积）；逐条追加的写放大（每条 AppendProgress 全量重写 tasks.json）。
func TestAdvIntFloodMetricsForFixes(t *testing.T) {
	now := float64(time.Now().UnixMilli()) / 1e3

	// A. 单批 10 万事件 → 计数封顶
	st1, err := store.Open(filepath.Join(t.TempDir(), "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.Create(&store.Task{ID: "m1", Target: "t1.invalid", Cmd: "icp",
		Status: store.StatusCreated, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	big := make([]store.ProgressEvent, 100000)
	for i := range big {
		big[i] = store.ProgressEvent{Ts: now, Module: "m", Event: "tick"}
	}
	st1.AppendProgress("m1", big)
	tk1, _ := st1.Get("m1")
	if len(tk1.Progress) > store.MaxProgress {
		t.Fatalf("单批 10 万事件应封顶 %d，得 %d", store.MaxProgress, len(tk1.Progress))
	}

	// B. 单条 5MB detail 炸弹 → 落盘体积实测
	dir2 := t.TempDir()
	st2, err := store.Open(filepath.Join(dir2, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Create(&store.Task{ID: "m2", Target: "t2.invalid", Cmd: "icp",
		Status: store.StatusCreated, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	st2.AppendProgress("m2", []store.ProgressEvent{{Ts: now, Module: "m", Event: "bomb",
		Detail: strings.Repeat("A", 5<<20)}})
	if data, err := os.ReadFile(filepath.Join(dir2, "tasks.json")); err == nil {
		t.Logf("5MB detail 炸弹后 tasks.json = %.1f MB（进度封顶只限条数不限单条体积）",
			float64(len(data))/(1<<20))
	}

	// C. 逐条追加写放大 → 200 条单事件追加耗时实测（每条一次全量重写）
	st3, err := store.Open(filepath.Join(t.TempDir(), "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st3.Create(&store.Task{ID: "m3", Target: "t3.invalid", Cmd: "icp",
		Status: store.StatusCreated, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	one := store.ProgressEvent{Ts: now, Module: "m", Event: "tick", Detail: "y"}
	t0 := time.Now()
	for i := 0; i < 200; i++ {
		st3.AppendProgress("m3", []store.ProgressEvent{one})
	}
	d := time.Since(t0)
	t.Logf("200 条单事件追加耗时 %s（均 %.2f ms/条；每条触发一次 tasks.json 全量重写）",
		d, float64(d.Microseconds())/200/1000)
}

// ── 5. 多任务并发互扰 ──

// TestAdvIntMultiTaskRealModulesNoCrossTalk 3 个真模块任务并发（两个不同靶站
// 的 api + 一个同目标任务共享产物目录的钉子 + 一个慢 paths），慢任务中途停：
// 完成者不受牵连全部 done、事件流水不串线、产物目录各归各、无任务停 running。
func TestAdvIntMultiTaskRealModulesNoCrossTalk(t *testing.T) {
	srvA := mockweb.New()
	defer srvA.Close()
	srvC := mockweb.New()
	defer srvC.Close()
	slow := newAdvSlowServer(t, 500*time.Millisecond)

	repo := t.TempDir()
	r := NewRunner(repo)
	sink := newFakeSink()
	r.SetSink(sink)

	targetA, targetC := srvA.URL+"/real", srvC.URL+"/real"
	mustStart := func(id, cmd, target string) {
		if err := r.Start(id, cmd, target, nil); err != nil {
			t.Fatalf("Start %s(%s → %s): %v", id, cmd, target, err)
		}
	}
	mustStart("adv-a", "api", targetA)
	mustStart("adv-c", "api", targetC)
	mustStart("adv-same", "api", targetA) // 同目标不同 ID：并发写共享产物目录的行为钉子
	mustStart("adv-slow", "paths", slow.srv.URL)

	// 慢任务进入逐项探测后中途停，其余任务必须照常跑完
	advWaitCond(t, 15*time.Second, "慢任务应进入扫描", func() bool { return slow.total.Load() >= 2 })
	if err := r.Stop("adv-slow"); err != nil {
		t.Fatalf("Stop adv-slow: %v", err)
	}
	for _, id := range []string{"adv-a", "adv-c", "adv-same"} {
		if st := waitTerminalFor(t, sink, id, 60*time.Second); st != store.StatusDone {
			t.Fatalf("%s 不受停慢牵连应完成 done，得 %q；事件=%+v", id, st, sink.eventsOf(id))
		}
	}
	if st := waitTerminalFor(t, sink, "adv-slow", 10*time.Second); st != store.StatusStopped {
		t.Fatalf("慢任务应 stopped，得 %q", st)
	}

	// 事件不串线：每任务流水里的模块级 start 只能是自己的 cmd
	for _, tc := range []struct{ id, cmd string }{
		{"adv-a", "api"}, {"adv-c", "api"}, {"adv-same", "api"}, {"adv-slow", "paths"},
	} {
		for _, ev := range sink.eventsOf(tc.id) {
			if ev.Event == "start" && ev.Module != tc.cmd {
				t.Fatalf("%s 的事件流水混入他模块 %s（cmd=%s）", tc.id, ev.Module, tc.cmd)
			}
		}
		if first, ok := func() (store.ProgressEvent, bool) {
			evs := sink.eventsOf(tc.id)
			if len(evs) == 0 {
				return store.ProgressEvent{}, false
			}
			return evs[0], true
		}(); !ok || first.Module != "pipeline" || first.Event != "pipeline_start" || first.Detail != tc.cmd {
			t.Fatalf("%s 首事件应为 pipeline_start(%s)，得 %+v", tc.id, tc.cmd, first)
		}
	}

	// 产物目录：不同目标各归各且非空；同目标任务共享同一目录（三方同名契约）
	dirA := filepath.Join(repo, "out", cli.OutdirName(targetA))
	dirC := filepath.Join(repo, "out", cli.OutdirName(targetC))
	for _, d := range []string{dirA, dirC} {
		entries, err := os.ReadDir(d)
		if err != nil || len(entries) == 0 {
			t.Fatalf("产物目录 %s 应存在非空: %v", d, err)
		}
	}
	if dirA == dirC {
		t.Fatal("不同目标的产物目录不得重名")
	}

	// 收尾状态机：无任务停在 running
	for _, id := range []string{"adv-a", "adv-c", "adv-same", "adv-slow"} {
		if st := sink.statusOf(id); st == store.StatusRunning || st == "" {
			t.Fatalf("%s 终态异常: %q", id, st)
		}
	}
}
