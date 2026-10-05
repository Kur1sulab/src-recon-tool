// Package cli：recon-go 的全部 CLI 逻辑（子命令分发表与公共小工具）。
// 从根 main.go 拆出，供两个薄入口共用：
//   - cmd/recon-go/main.go（标准布局入口，go build ./cmd/recon-go）
//   - 根 main.go（兼容旧验收命令 go build -o recon-go.exe .）
package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/apiunauth"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/asset"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/baseline"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/paths"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/poc"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/report"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/reverseip"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/subdomain"
)

const helpText = `recon-go — SRC 信息收集自动化工具（Go 引擎，仅限授权测试）

用法（DOMAIN 或 IP 都吃，工具自动识别）:
  recon-go all -t example.com             # 一键全流程未实现（exit 2）——请用 python src/recon.py all
  recon-go subdomain -d example.com [--verify]
  recon-go verify -d example.com [-w 8]
  recon-go asset -d example.com           # ✅ c2（key 走 FOFA_EMAIL/FOFA_KEY、HUNTER_KEY）
  recon-go reverse -i 47.100.49.228       # ✅ c2
  recon-go icp -d example.com             # ✅ c2（APIHZ_ID/APIHZ_KEY 可覆盖）
  recon-go api -u https://example.com     # ✅ c2（含取证模式）
  recon-go jsintel -u https://example.com # 暂不移植（c3 拍板，exit 2）
  recon-go portscan -t 47.100.49.228      # 暂不移植（c3 拍板，exit 2）
  recon-go fingerprint -u https://example.com
  recon-go paths -u https://example.com   # ✅ c2
  recon-go baseline -d example.com [--checks secheaders,webfiles]  # ✅ c2（域名暴露面基线 8 检查）
  recon-go poc -t https://example.com -p pocs/example.yaml  # ✅ c2（YAML 引擎）
  recon-go llm -d example.com             # 已弃用，Go 版不移植（exit 2）
  recon-go report -t example.com          # ✅ c2（资产档案+证据包）
`

// knownCmds 合法子命令集合（argparse 在解析阶段即拒绝未知子命令，进度事件
// 不发——故 Run 只对集合内子命令包事件流）。与 recon.py:164-187 的子解析器一一对应。
var knownCmds = map[string]bool{
	"all": true, "subdomain": true, "verify": true, "asset": true, "reverse": true,
	"icp": true, "api": true, "fingerprint": true, "paths": true, "jsintel": true,
	"portscan": true, "poc": true, "llm": true, "report": true,
	"baseline": true, // 域名暴露面基线（report §5.9；桌面第二子进程，非 Python recon.py 对齐项）
}

// Run 处理全局参数与子命令（args 不含程序名），返回进程退出码。
// 14 个子命令与 Python recon.py:137-212 一一对齐；本轮（c1）真实现
// subdomain / verify / fingerprint，其余注册占位并 exit 2（防静默走错分支），
// llm 按铁律不移植、明确弃用。
//
// fix1（审计 medium#4）：补齐 --progress-file 全局参数层——桌面壳
// desktop-go/internal/engine/runner.go 以「--progress-file 在子命令之前」为契约
// 驱动进度状态机，事件键序与 recon.py:31-62 逐项对齐（见 progress.go）。
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Print(helpText)
		return 1
	}
	rest, code := applyProgressFile(args)
	if rest == nil {
		if code == -1 { // -h/--help/help：等价 argparse 阶段退出，不发事件
			fmt.Print(helpText)
			return 0
		}
		return code
	}
	if progressFile == "" {
		// 对齐 recon.py:191：CLI 参数缺省时回退环境变量 RECON_PROGRESS_FILE
		progressFile = os.Getenv("RECON_PROGRESS_FILE")
	}
	cmd := rest[0]
	// fix3（audit low#6）：argparse 无 help 子命令——`recon.py help` 是未知
	// 选择，解析阶段 exit 2（不发事件）；-h/--help 全局帮助仍 exit 0
	if !knownCmds[cmd] {
		// 对齐 argparse：未知子命令在解析阶段 exit 2，事件流不启动
		fmt.Printf("[*] 未知子命令: %q\n\n", cmd)
		fmt.Print(helpText)
		return 2
	}
	emit("pipeline_start", "pipeline", cmd)
	if cmd != "all" {
		emit("start", cmd, "")
	}
	code = dispatch(cmd, rest[1:])
	switch {
	case cmd == "all": // recon.py:250-256：all 无模块级收尾事件
		if code == 0 {
			emit("pipeline_end", "pipeline", "done")
		} else {
			emit("pipeline_end", "pipeline", "fail")
		}
	case code == 0:
		emit("done", cmd, "")
		emit("pipeline_end", "pipeline", "done")
	default:
		emit("fail", cmd, fmt.Sprintf("exit %d", code))
		emit("pipeline_end", "pipeline", "fail")
	}
	return code
}

func dispatch(cmd string, rest []string) int {
	switch cmd {
	case "subdomain":
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		verify := fs.Bool("verify", false, "枚举后立即做存活验证（DNS + HTTP）")
		if c := parseOrUsage(fs, rest, cmd, "subdomain -d <domain> [--verify]"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "subdomain -d <domain> [--verify]")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1 // 对齐 Python：os.makedirs 抛 OSError 未捕获 → exit 1
		}
		if _, err := subdomain.Run(d, out); err != nil {
			return 1 // fix3：写盘失败 → fail 事件 + exit 1（对齐 Python safe_write 抛错）
		}
		if *verify {
			subdomain.RunVerify(out, 8, true)
		}
		return 0

	case "verify":
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		workers := fs.Int("w", 8, "")
		workersAlias := fs.Int("workers", 8, "")
		if c := parseOrUsage(fs, rest, cmd, "verify -d <domain> [-w workers]"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "verify -d <domain> [-w workers]")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		subdomain.RunVerify(out, pickIntAliasLastWins(rest, 8, map[string]*int{"-w": workers, "--workers": workersAlias}), true)
		return 0

	case "fingerprint":
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if c := parseOrUsage(fs, rest, cmd, "fingerprint -u <url>"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "fingerprint -u <url>")
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		fingerprint.RunFingerprint(url, out)
		return 0

	case "llm":
		// 铁律：llm 模块（可选增强）不移植。
		fmt.Println("[*] llm 模块已弃用：Go 版不移植（原 Python 侧为可选增强，详见 engine-go/README.md）")
		return 2

	case "asset": // recon.py:177-178：asset -d/--domain
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		if c := parseOrUsage(fs, rest, cmd, "asset -d <domain>"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "asset -d <domain>")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		asset.RunAsset(d, out)
		return 0

	case "reverse": // recon.py:179-180：reverse -i/--ip
		fs := newFlagSet()
		ip := fs.String("i", "", "")
		ipAlias := fs.String("ip", "", "")
		if c := parseOrUsage(fs, rest, cmd, "reverse -i <ip>"); c != -1 {
			return c
		}
		target := pickAliasLastWins(rest, map[string]*string{"-i": ip, "--ip": ipAlias})
		if target == "" {
			return missingArgs(cmd, "reverse -i <ip>")
		}
		// fix2 P3：严格 IP 校验——`reverse -i '8.8.8.8&x=1'` 这类注入形态参数
		// 在入口拒绝（对抗实测曾照单全收拼进数据源 URL）。Go 侧 fail-closed，
		// Python 侧维持原行为，差异记入 README 已知微差。
		if net.ParseIP(target) == nil {
			fmt.Printf("[!] 非法 IP: %q（reverse -i 需要合法 IPv4/IPv6 地址）\n", target)
			return 2
		}
		out, err := MakeOutdir(target)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		reverseip.RunReverse(target, out)
		return 0

	case "icp": // recon.py:182-183：icp -d/--domain
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		if c := parseOrUsage(fs, rest, cmd, "icp -d <domain>"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "icp -d <domain>")
		}
		// fix2 P3：域名形状校验（与 subdomain 入口污点闸同规则），注入/路径
		// 形态在入口拒绝，不进任何第三方查询。
		if bad, why := invalidDomainShape(d); bad {
			fmt.Printf("[!] 非法域名（%s）: %q\n", why, d)
			return 2
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		icp.RunICP(d, out)
		return 0

	case "api": // recon.py:185-186：api -u/--url（含取证模式）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if c := parseOrUsage(fs, rest, cmd, "api -u <url>"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "api -u <url>")
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if _, err := apiunauth.RunAPI(url, out, true); err != nil {
			return 1 // fix3：写盘失败 → fail 事件 + exit 1
		}
		return 0

	case "paths": // recon.py:191-192：paths -u/--url（Go 侧补 --extra 补充字典，report §5.2）
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		extraFile := fs.String("extra", "", "补充字典文件（一行一路径，如 baseline webfiles 的 paths_extra.txt）")
		if c := parseOrUsage(fs, rest, cmd, "paths -u <url> [--extra <file>]"); c != -1 {
			return c
		}
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			return missingArgs(cmd, "paths -u <url> [--extra <file>]")
		}
		var extra []string
		if path := strings.TrimSpace(*extraFile); path != "" {
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				fmt.Printf("[!] --extra 文件读取失败: %v\n", rerr)
				return 2
			}
			for _, ln := range strings.Split(string(b), "\n") {
				extra = append(extra, strings.TrimSpace(ln))
			}
		}
		out, err := MakeOutdir(url)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if _, err := paths.RunPaths(url, out, extra...); err != nil {
			return 1 // fix3：写盘失败 → fail 事件 + exit 1
		}
		return 0

	case "poc": // recon.py:198-199：poc -t/--target -p/--poc
		fs := newFlagSet()
		target := fs.String("t", "", "")
		pocFile := fs.String("p", "", "")
		if c := parseOrUsage(fs, rest, cmd, "poc -t <target> -p <poc>"); c != -1 {
			return c
		}
		if *target == "" || *pocFile == "" {
			return missingArgs(cmd, "poc -t <target> -p <poc>")
		}
		poc.RunPOC(*target, *pocFile) // recon.py 不以命中与否改变退出码
		return 0

	case "report": // recon.py:204-206：report -t/--target -d/--domain（dest=target）
		fs := newFlagSet()
		target := fs.String("t", "", "")
		targetAlias := fs.String("target", "", "")
		domainAlias := fs.String("d", "", "")
		if c := parseOrUsage(fs, rest, cmd, "report -t <target>"); c != -1 {
			return c
		}
		t := pickAliasLastWins(rest, map[string]*string{"-t": target, "--target": targetAlias, "-d": domainAlias})
		if t == "" {
			return missingArgs(cmd, "report -t <target>")
		}
		out, err := MakeOutdir(t)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		if report.RunReport(out, t) == "" {
			return 1 // fix3：report.md 写盘失败（RunReport 以 "" 标记）→ fail 事件 + exit 1
		}
		return 0

	case "baseline": // report §5.9：域名暴露面基线 8 检查聚合（-d 必填 + 形状校验 + --checks 过滤）
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		checks := fs.String("checks", "", "逗号分隔检查名过滤（默认全跑 8 项）")
		if c := parseOrUsage(fs, rest, cmd, "baseline -d <domain> [-u <url>] [--checks c1,c2,...]"); c != -1 {
			return c
		}
		d := pickAliasLastWins(rest, map[string]*string{"-d": domain, "--domain": domainAlias})
		if d == "" {
			return missingArgs(cmd, "baseline -d <domain> [-u <url>] [--checks c1,c2,...]")
		}
		// 域名形状校验（与 icp 同闸，注入/路径形态入口拒绝）
		if bad, why := invalidDomainShape(d); bad {
			fmt.Printf("[!] 非法域名（%s）: %q\n", why, d)
			return 2
		}
		// --checks 归一化在 MakeOutdir/PickBase 之前（未知检查名 exit 2，零网络副作用）
		checkNames := []string(nil)
		if strings.TrimSpace(*checks) != "" {
			var err error
			checkNames, err = baseline.NormalizeChecks(strings.Split(*checks, ","))
			if err != nil {
				fmt.Printf("[!] %v\n", err)
				return 2
			}
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		// -u 缺省：HTTP 类检查入口从域名推导（PickBase 探测 https/http，
		// 全失败回退 https://<d>；桌面首版只传 -d 时走此分支）
		url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
		if url == "" {
			url = PickBase(d)
		}
		if err := baseline.Run(baseline.Options{
			Domain: d, URL: url, Out: out, Checks: checkNames,
			AllowPrivate: true, // 桌面契约：授权内网目标放行（白名单由桌面线守）
			Emit:         emit,
			Logf:         func(f string, a ...any) { fmt.Printf(f, a...) },
		}); err != nil {
			fmt.Printf("[!] baseline: %v\n", err)
			return 1 // 聚合器自身错误（未知检查名兜底/outdir）→ fail + exit 1
		}
		return 0

	case "all", "jsintel", "portscan":
		// c3 拍板（终态）：all/jsintel/portscan 维持不实现——exit 2 防静默走错，
		// 全流程/JS 情报/端口扫描请用 Python 版（python src/recon.py all 等）。
		switch cmd {
		case "all":
			fmt.Println("[*] recon-go: 子命令 \"all\" 不实现（一键全流程请用 python src/recon.py all）")
		default:
			fmt.Printf("[*] recon-go: 子命令 %q 暂不移植（如需该能力请用 python src/recon.py %s）\n", cmd, cmd)
		}
		return 2

	case "help", "-h", "--help":
		fmt.Print(helpText)
		return 0

	default:
		fmt.Printf("[*] 未知子命令: %q\n\n", cmd)
		fmt.Print(helpText)
		return 2
	}
}

// ── 与 recon.py:30-63 对齐的公共小工具 ──

// IsIP 等价 recon.py:65-70 is_ip（ipaddress.ip_address 可解析即真）。
// fix1（审计 low#9）：不做 TrimSpace——Python ip_address(" 1.2.3.4 ") 判假，
// 此前 Go 侧 trim 后判真，属潜伏契约差异（c2 轮 all 实现时会生效）。
func IsIP(s string) bool { return net.ParseIP(s) != nil }

// outdirNameReplacer 目标 → 目录名清洗（fix1 P1，与 Python recon.py make_outdir
// 同步改，两引擎必须产出同名目录）：在原 :// 、/ 、: 基础上补齐
// 反斜杠（Windows 路径分隔符，防 ..\.. 逃逸出 out/）与 Windows 非法字符
// ? & = " < > | *（此前 query 原样进目录名：Windows 直接 mkdir 语法错误，
// Linux 则把含潜在 api_key 的完整 query 持久化进文件系统路径）。
var outdirNameReplacer = strings.NewReplacer(
	"://", "_", "/", "_", "\\", "_", ":", "_",
	"?", "_", "&", "_", "=", "_", `"`, "_",
	"<", "_", ">", "_", "|", "_", "*", "_",
)

// MakeOutdir 等价 recon.py:73-76：out/<target 清洗>。
// fix1（审计 medium#2 / low#6）：
//   - 清洗后剔首尾点号与空格；结果为空或 ".."（纯穿越锚）回 "unknown"——
//     此前 "..\..\x" 换 \ 后仍可能残留 ".." 组件，os.MkdirAll 在 out/ 之外
//     创建目录（实测逃逸两级）；
//   - MkdirAll 失败上抛给调用方（CLI 打印后 exit 1），对齐 Python os.makedirs
//     抛 OSError 未捕获 → exit 1 的退出码契约；不再吞错继续走完流程。
func MakeOutdir(target string) (string, error) {
	name := outdirNameReplacer.Replace(target)
	name = strings.Trim(name, ". ")
	if name == "" || name == ".." {
		name = "unknown"
	}
	// fix2 P3：Windows 保留设备名主干（con/nul/aux/com1-9/lpt1-9）与
	// SafeFilename 同规则补 _——实测 `report -t CON` 会在本机建出 out\CON，
	// 与文件层加固不一致。Python make_outdir / desktop outDirFor 同步。
	name = netutil.DefuseWindowsReservedStem(name)
	out := "out" + string(os.PathSeparator) + name
	if err := os.MkdirAll(out, 0o755); err != nil {
		return out, err
	}
	return out, nil
}

// PickBase 等价 recon.py:44-63：优先 https，status<500 即用，失败退 http。
// 授权测试允许内网目标，故显式 allowPrivate=true 放行私网（c2 轮 all 命令使用）。
// fix1 P1：Follow 模式逐跳复验重定向落点（与入口同策略），与 RunFingerprint 一致。
func PickBase(host string) string {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		checked, err := netutil.CheckHTTPURL(url, true)
		if err != nil {
			continue
		}
		r := netutil.Fetch(checked, netutil.FetchOpt{Timeout: 10 * time.Second, Follow: true,
			HopCheck: netutil.HopPolicy(checked)})
		if r.OK && r.Status > 0 && r.Status < 500 {
			return checked
		}
	}
	return "https://" + host
}

// ── flag 辅助 ──

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(discard{})
	return fs
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func parseOrUsage(fs *flag.FlagSet, args []string, cmd, usage string) int {
	err := fs.Parse(args)
	if err == nil {
		return -1
	}
	if errors.Is(err, flag.ErrHelp) {
		// fix3（audit low#6）：子命令内 -h/--help 对齐 argparse——打印本命令
		// 用法后 exit 0（此前 flag 包报参数错误 exit 2）
		fmt.Printf("用法: recon-go %s\n", usage)
		fs.PrintDefaults()
		return 0
	}
	fmt.Printf("[!] 参数错误: %v\n  用法: recon-go %s\n", err, usage)
	return 2
}

func missingArgs(cmd, usage string) int {
	fmt.Printf("[!] 缺少必填参数（subcommand=%s）\n  用法: recon-go %s\n", cmd, usage)
	return 2
}

// pickAliasLastWins 重复旗标取「命令行中最后出现」者的值（argparse last-wins
// 语义，fix2 audit low#7：此前 pickNonEmpty 取第一个非空，与 Python 相反——
// `verify -w 16 --workers 8` Go 得 16、Python 得 8）。fs.Visit 是字典序而非
// 命令行序，故按原始 args 里各别名的最后出现位置判定。
// 未显式设置任何别名时返回零值""（由调用方走 missingArgs）。
func pickAliasLastWins(args []string, vals map[string]*string) string {
	norm := map[string]*string{}
	for k, v := range vals {
		norm[strings.TrimLeft(k, "-")] = v // vals 键带横线；args token 无横线
	}
	lastPos := map[string]int{}
	for i, tk := range args {
		name := strings.TrimLeft(tk, "-")
		if j := strings.IndexByte(name, '='); j >= 0 {
			name = name[:j]
		}
		if _, isAlias := norm[name]; isAlias {
			lastPos[name] = i
		}
	}
	best, picked := -1, ""
	for name, p := range norm {
		if o, ok := lastPos[name]; ok && o > best {
			best, picked = o, *p
		}
	}
	return picked
}

// pickIntAliasLastWins 同 pickAliasLastWins 的 int 版；全部未设置回 def。
func pickIntAliasLastWins(args []string, def int, vals map[string]*int) int {
	norm := map[string]*int{}
	for k, v := range vals {
		norm[strings.TrimLeft(k, "-")] = v
	}
	lastPos := map[string]int{}
	for i, tk := range args {
		name := strings.TrimLeft(tk, "-")
		if j := strings.IndexByte(name, '='); j >= 0 {
			name = name[:j]
		}
		if _, isAlias := norm[name]; isAlias {
			lastPos[name] = i
		}
	}
	best, picked, any := -1, def, false
	for name, p := range norm {
		if o, ok := lastPos[name]; ok && o > best {
			best, picked, any = o, *p, true
		}
	}
	if !any {
		return def
	}
	return picked
}

// invalidDomainShape 域名形状白名单（与 subdomain.Run 入口污点闸同规则）：
// 非空、≤253、无路径分隔符/悬浮点组件/控制字符。bad=true 时 why 给出原因。
func invalidDomainShape(d string) (bool, string) {
	v := strings.TrimSpace(d)
	switch {
	case v == "":
		return true, "空"
	case len(v) > 253:
		return true, "超长"
	case strings.ContainsAny(v, `/\`):
		return true, "含路径分隔符"
	case strings.Contains(v, ".."):
		return true, "含悬浮点组件"
	case strings.ContainsFunc(v, func(r rune) bool { return r <= 0x20 || r == 0x7f }):
		return true, "含控制字符/空白"
	case strings.ContainsFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '.' || r == '-')
	}):
		return true, "含域名合法字符集之外的字符（&=?# 等）"
	}
	return false, ""
}

func pickNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pickNonEmpty3 三个候选里取第一个非空值。
func pickNonEmpty3(a, b, c string) string {
	if a != "" {
		return a
	}
	return pickNonEmpty(b, c)
}

// pickInt 取非默认值者优先，两个都等于默认则回默认。
func pickInt(a, b, def int) int {
	if a != def {
		return a
	}
	return b
}
