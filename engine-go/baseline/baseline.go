// Package baseline：域名暴露面基线体检（8 项零凭据检查），落地
// RESEARCH-webcheck-20261005.md §5.0-5.9 的设计。聚合子命令：
//
//	recon-go baseline -d <domain> [-u <url>] [--checks secheaders,webfiles,...]
//
// 8 个检查：secheaders(§5.1) webfiles(§5.2) mailsec(§5.3) archives(§5.4)
// sslchain(§5.5) dnsrec(§5.6) whois(§5.7) geoasn(§5.8)。
//
// 命名澄清：本包与 netutil.Baseline（软 404 catch-all 探针，netutil/baseline.go）
// 是两个概念——前者是「暴露面体检基线」，后者是「软 404 响应基线」。本包内对
// 软 404 探针的引用一律带 netutil. 限定符。
//
// 纪律（§5.0）：全部检查零 key 必需；外联仅免 key 公开源——archives/whois/
// geoasn 的免 key 外联是模块本体、默认开；dnsrec 的 DoH 与 whois 的 tranco
// 默认关（--doh/--rank 显式开启）；目标请求前过 netutil.CheckHTTPURL 边界校验
// （allowPrivate 放行授权内网靶标）；全部 Go 标准库，go.mod 零新增 require。
//
// 进度契约（§5.9 / 桌面执行器裁决）：外层 start/done(module=baseline) 与
// pipeline_start/pipeline_end 由 cli.Run 发；本聚合器只发内层每检查
// start/done|fail|skipped(module=检查名)。个别检查 fail（Result.Error 非空）
// 不改变聚合终态，聚合器自身错误（目标非法/outdir 不可建）才上抛 error。
package baseline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// 8 个检查名（= 产物文件名主干，桌面 outDirFor 三方同名目录契约）。
const (
	CheckSecHeaders = "secheaders"
	CheckWebfiles   = "webfiles"
	CheckMailsec    = "mailsec"
	CheckArchives   = "archives"
	CheckSSLChain   = "sslchain"
	CheckDNSRec     = "dnsrec"
	CheckWhois      = "whois"
	CheckGeoASN     = "geoasn"
)

// checksOrder 聚合执行顺序（报告 §5.1-5.8 编号序）。
var checksOrder = []string{
	CheckSecHeaders, CheckWebfiles, CheckMailsec, CheckArchives,
	CheckSSLChain, CheckDNSRec, CheckWhois, CheckGeoASN,
}

// checkAliases --checks 接受的报告原文写法别名。
var checkAliases = map[string]string{
	"sec_headers": CheckSecHeaders,
	"ssl_chain":   CheckSSLChain,
}

// CheckLabels 检查名 → 中文名（CLI 输出与 report.md 章节共用）。
var CheckLabels = map[string]string{
	CheckSecHeaders: "安全响应头",
	CheckWebfiles:   "网站文件",
	CheckMailsec:    "邮件安全",
	CheckArchives:   "历史归档",
	CheckSSLChain:   "TLS 证书链",
	CheckDNSRec:     "DNS 记录",
	CheckWhois:      "WHOIS 注册信息",
	CheckGeoASN:     "IP 归属 / ASN",
}

// ErrUnknownCheck --checks 含未知检查名（CLI exit 2）。
var ErrUnknownCheck = errors.New("未知检查名")

// NormalizeChecks --checks 过滤归一化：空/nil = 全部 8 项；接受 checkAliases
// 别名；按 checksOrder 排序输出、去重；未知名返回 ErrUnknownCheck。
func NormalizeChecks(names []string) ([]string, error) {
	if len(names) == 0 {
		return append([]string(nil), checksOrder...), nil
	}
	want := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if canon, ok := checkAliases[n]; ok {
			n = canon
		}
		if _, known := CheckLabels[n]; !known {
			return nil, fmt.Errorf("%w: %q（合法: %s）", ErrUnknownCheck, n, strings.Join(checksOrder, ","))
		}
		want[n] = true
	}
	out := make([]string, 0, len(want))
	for _, c := range checksOrder {
		if want[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

// Options 聚合参数。URL 为可选显式入口（CLI 缺省时以 PickBase 推导后传入；
// 包直用时 HTTP 类检查回退 https://<domain>）。
type Options struct {
	Domain string
	URL    string
	Out    string
	Checks []string // 归一化前的过滤名单；空 = 全部

	AllowPrivate bool                // 目标私网放行（授权内网靶标，CLI 恒 true）
	DoH          bool                // dnsrec：DoH 查 SOA/CAA/DS/DNSKEY（默认关，§5.6）
	Rank         bool                // whois：tranco 排名（默认关，§5.7）
	Ports        []string            // sslchain：443 之外的扩展端口
	IPs          []string            // geoasn：直传 IP（空 = 域名 A 记录解析）
	KnownA       map[string][]string // dnsrec：verify 已解析 A 记录（去重免二次查询）

	PerCheckTimeout time.Duration // 0 = 60s/项（§5.9）
	TotalBudget     time.Duration // 0 = 5min 总预算（§5.9）

	Emit func(event, module, detail string) // 进度事件（nil = 关）
	Logf func(format string, args ...any)   // 控制台日志（nil = 静默）

	// Ctx（第一步「取消能力注入」③）：取消分两档（终修轮收紧）——已起步的
	// 在跑检查由 runOne 的 select ctx.Done 分支提前返回「已取消」失败包络，
	// 照实落盘（它确实跑过）；未起步检查由 RunContext 循环头检查点拦截，
	// 只发 skipped 事件、不落产物（缺文件 = 未运行，桌面不渲染成失败）。
	// 检查内部请求经 netutil 取消咽喉随 ctx 立即失败。
	// nil = 不取消（等价 context.Background()，存量调用零改动）。
	Ctx context.Context
}

// checkFuncs 检查注册表（各检查文件实现）。
var checkFuncs = map[string]func(Options) Result{
	CheckSecHeaders: RunSecHeaders,
	CheckWebfiles:   RunWebfiles,
	CheckMailsec:    RunMailsec,
	CheckArchives:   RunArchives,
	CheckSSLChain:   RunSSLChain,
	CheckDNSRec:     RunDNSRec,
	CheckWhois:      RunWhois,
	CheckGeoASN:     RunGeoASN,
}

// Run 聚合器：串行跑选中检查（§5.9），每检查独立超时、总预算封顶；
// 逐检查落盘 <check>.json + <check>.txt + evidence/baseline/<check>.json 副本
// （report.PackEvidence 的 out/evidence/ 打包范围，§5.0）；超预算的剩余检查发
// skipped 事件且不落盘（缺文件 = 未运行）。返回 error 仅限聚合器自身错误
// （未知检查名）；检查级失败走 Result.Error + fail 事件，不上抛。
func Run(o Options) error {
	return RunContext(context.Background(), o)
}

// RunContext 是 Run 的取消变体（第一步「取消能力注入」①）：首参 ctx 写入
// Options.Ctx，聚合循环与 runOne 据此提前收敛；旧 Run(...) 委托本函数，
// cli.go 调用点与存量测试零改动。
func RunContext(ctx context.Context, o Options) error {
	o.Ctx = ctx
	checks, err := NormalizeChecks(o.Checks)
	if err != nil {
		return err
	}
	if o.Domain == "" {
		return errors.New("baseline: 目标域名为空")
	}
	if o.PerCheckTimeout <= 0 {
		o.PerCheckTimeout = 60 * time.Second
	}
	if o.TotalBudget <= 0 {
		o.TotalBudget = 5 * time.Minute
	}
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	emit := o.Emit
	if emit == nil {
		emit = func(string, string, string) {}
	}
	start := nowFn()
	for i, c := range checks {
		// 取消检查点（终修轮）：Stop 后剩余检查不再 emit start/fail、不落
		// 「已取消」占位产物——桌面契约「缺文件 = 未运行」，不把没跑过的
		// 检查渲染成红「失败」（此前取消后剩余检查逐个写成取消包络，桌面
		// 按 Error 非空全部显示失败）。与下方总预算耗尽分支同构发 skipped，
		// 文案如实注明未运行。
		if err := ctx.Err(); err != nil {
			emit("skipped", c, fmt.Sprintf("已取消，未运行（%v）", err))
			logf("[!] 基线检查 %d/%d %s（%s）未运行：已取消", i+1, len(checks), CheckLabels[c], c)
			continue
		}
		// 从 start 起算已耗时间（不用 deadline 比较：Windows 时钟粒度粗，
		// 同 tick 内 start.Add(1ns) 仍可能被判未到期）
		if nowFn().Sub(start) >= o.TotalBudget {
			emit("skipped", c, fmt.Sprintf("总预算耗尽（%s），未运行", o.TotalBudget))
			logf("[!] 基线检查 %d/%d %s（%s）跳过：总预算耗尽", i+1, len(checks), CheckLabels[c], c)
			continue
		}
		emit("start", c, "")
		logf("[*] 基线检查 %d/%d: %s（%s）", i+1, len(checks), CheckLabels[c], c)
		res := runOne(c, o, o.PerCheckTimeout)
		if werr := writeProducts(o, res, logf); werr != nil {
			return werr // 产物写盘失败属聚合器自身错误 → CLI fail + exit 1
		}
		if res.Error != "" {
			emit("fail", c, res.Error)
		} else {
			emit("done", c, "")
		}
	}
	return nil
}

// runOne 单检查执行 + 硬超时护栏（§5.9：默认 60s/项）。超时返回失败包络
// （检查 goroutine 无法强杀，其结果被丢弃；各检查内部请求均有自身超时，
// 外层护栏只兜聚合流程不卡死）。第一步③：Options.Ctx 已取消时 select 的
// ctx.Done 分支提前返回「已取消」包络，不再等检查跑完——该分支只作用于
// 已起步的在跑检查；未起步检查由 RunContext 循环头的检查点拦截（不发
// start/fail、不落产物）。
func runOne(check string, o Options, timeout time.Duration) Result {
	ch := make(chan Result, 1)
	go func() { ch <- safeCheck(check, o) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case res := <-ch:
		return res
	case <-timer.C:
		res := NewResult(check, o.Domain, o.URL)
		res.Error = fmt.Sprintf("检查超时（%s 预算耗尽）", timeout)
		res.Conclusion = Conclusion{Level: LevelFail, Text: "执行超时，未取得完整结果"}
		return res
	case <-ctx.Done():
		res := NewResult(check, o.Domain, o.URL)
		res.Error = fmt.Sprintf("已取消（%v）", ctx.Err())
		res.Conclusion = Conclusion{Level: LevelFail, Text: "执行已取消，未取得完整结果"}
		return res
	}
}

// safeCheck 检查实现 panic 兜底（终修轮，审计 high#1）：直调重写后检查在
// 宿主进程内跑（桌面 exe / 第三方嵌入方），敌意远端数据引爆任一检查实现
// （JSON 类型断言/切片越界/TLS 解析）此前会炸穿整个进程——就地把 panic 转
// 「已取消/超时」同型的失败包络，检查级失败照常落盘、不上抛。recover 只能
// 兜本 goroutine：检查内部自起的 worker goroutine（dnsrec 池）不在本兜底面，
// 嵌入方契约见 README「进程内嵌入」一节。
func safeCheck(check string, o Options) (res Result) {
	defer func() {
		if p := recover(); p != nil {
			res = NewResult(check, o.Domain, o.URL)
			res.Error = fmt.Sprintf("检查实现异常（panic 已兜底）：%v", p)
			res.Conclusion = Conclusion{Level: LevelFail, Text: "引擎内部异常，未取得完整结果"}
		}
	}()
	return checkFuncs[check](o)
}

// writeProducts 落盘 json + txt + 证据副本。
func writeProducts(o Options, res Result, logf func(string, ...any)) error {
	body := jsonx.Pretty(res)
	if _, err := netutil.SafeWrite(o.Out, res.Check+".json", body); err != nil {
		return fmt.Errorf("baseline: %s.json 写盘失败: %w", res.Check, err)
	}
	if _, err := netutil.SafeWrite(o.Out, res.Check+".txt", renderTxt(res)); err != nil {
		logf("[!] %s.txt 写盘失败（不影响主产物）: %v", res.Check, err)
	}
	// 证据包收口（§5.0：基线 json 收进 out/evidence/，report.PackEvidence 打包范围）
	if d, err := netutil.SafeSubdir(o.Out, "evidence", "baseline"); err == nil {
		if _, err := netutil.SafeWrite(d, res.Check+".json", body); err != nil {
			logf("[!] 证据副本写盘失败（不影响主产物）: %v", err)
		}
	}
	if res.Error != "" {
		logf("[!] %s（%s）执行失败: %s", CheckLabels[res.Check], res.Check, res.Error)
	} else {
		logf("[+] %s（%s）完成: %s", CheckLabels[res.Check], res.Check, res.Conclusion.Text)
	}
	return nil
}

// renderTxt 人类可读摘要（txt 产物）：结论 + 风险 + 各检查塞进
// Data["summary"] 的可读行。
func renderTxt(res Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "域名暴露面基线 · %s（%s）\n", CheckLabels[res.Check], res.Check)
	fmt.Fprintf(&b, "目标: %s", res.Target)
	if res.URL != "" {
		fmt.Fprintf(&b, "  入口: %s", res.URL)
	}
	fmt.Fprintf(&b, "  时间: %s\n", res.GeneratedAt)
	if res.Error != "" {
		fmt.Fprintf(&b, "执行失败: %s\n", res.Error)
	} else {
		fmt.Fprintf(&b, "结论[%s]: %s\n", res.Conclusion.Level, res.Conclusion.Text)
	}
	if len(res.Risks) > 0 {
		b.WriteString("风险:\n")
		for _, r := range res.Risks {
			fmt.Fprintf(&b, "  [%s] %s", r.Level, r.Title)
			if r.Detail != "" {
				fmt.Fprintf(&b, " — %s", r.Detail)
			}
			b.WriteString("\n")
		}
	}
	if sums, ok := res.Data["summary"].([]string); ok {
		b.WriteString("摘要:\n")
		for _, s := range sums {
			fmt.Fprintf(&b, "  %s\n", s)
		}
	}
	return b.String()
}

// baseEntry HTTP 类检查的入口 URL：显式 URL 优先，回退 https://<domain>。
// 请求前过 CheckHTTPURL 边界校验（allowPrivate 放行授权内网），失败返回 error。
func baseEntry(o Options) (string, error) {
	entry := o.URL
	if entry == "" {
		entry = "https://" + o.Domain
	}
	return netutil.CheckHTTPURL(entry, o.AllowPrivate)
}

// ── DNS 查询抽象（mailsec §5.3 / dnsrec §5.6 共用；测试注入假实现）──

// 类型别名：测试与生产共用 stdlib 形态。
type (
	netMX     = net.MX
	netIPAddr = net.IPAddr
	netNS     = net.NS
	netSRV    = net.SRV
)

func ipV4(a, b, c, d byte) net.IP { return net.IPv4(a, b, c, d) }

// dnsClient DNS 查询抽象。生产实现包 net.DefaultResolver；单测注入固定记录。
type dnsClient interface {
	LookupMX(ctx context.Context, domain string) ([]*netMX, error)
	LookupTXT(ctx context.Context, domain string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]netIPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNS(ctx context.Context, host string) ([]*netNS, error)
	LookupSRV(ctx context.Context, service, proto, domain string) (string, []*netSRV, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// prodDNS 生产实现（net.DefaultResolver）。
type prodDNS struct{}

func (prodDNS) LookupMX(ctx context.Context, domain string) ([]*netMX, error) {
	return net.DefaultResolver.LookupMX(ctx, domain)
}
func (prodDNS) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, domain)
}
func (prodDNS) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}
func (prodDNS) LookupIP(ctx context.Context, network, host string) ([]netIPAddr, error) {
	// go1.24 net.Resolver.LookupIP 返回 []net.IP（非 Addr），包装成统一形态
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netIPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, netIPAddr{IP: ip})
	}
	return out, nil
}
func (prodDNS) LookupCNAME(ctx context.Context, host string) (string, error) {
	return net.DefaultResolver.LookupCNAME(ctx, host)
}
func (prodDNS) LookupNS(ctx context.Context, host string) ([]*netNS, error) {
	return net.DefaultResolver.LookupNS(ctx, host)
}
func (prodDNS) LookupSRV(ctx context.Context, service, proto, domain string) (string, []*netSRV, error) {
	return net.DefaultResolver.LookupSRV(ctx, service, proto, domain)
}
func (prodDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// dns 解析器实例（可注入；包级变量沿用 icp.APIHZURL 的注入惯例）。
var dns dnsClient = prodDNS{}

// dnsTimeout 单查询超时（§5.6：3 秒，对齐 verify 风格）。
const dnsTimeout = 3 * time.Second
