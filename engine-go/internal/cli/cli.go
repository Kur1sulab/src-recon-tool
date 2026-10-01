// Package cli：recon-go 的全部 CLI 逻辑（子命令分发表与公共小工具）。
// 从根 main.go 拆出，供两个薄入口共用：
//   - cmd/recon-go/main.go（标准布局入口，go build ./cmd/recon-go）
//   - 根 main.go（兼容旧验收命令 go build -o recon-go.exe .）
package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/subdomain"
)

const helpText = `recon-go — SRC 信息收集自动化工具（Go 引擎，仅限授权测试）

用法（DOMAIN 或 IP 都吃，工具自动识别）:
  recon-go all -t example.com             # 域名/IP 全流程（c2 轮实现）
  recon-go subdomain -d example.com [--verify]
  recon-go verify -d example.com [-w 8]
  recon-go asset -d example.com           # c2 轮实现
  recon-go reverse -i 47.100.49.228       # c2 轮实现
  recon-go icp -d example.com             # c2 轮实现
  recon-go api -u https://example.com     # c2 轮实现
  recon-go jsintel -u https://example.com # c2 轮实现
  recon-go portscan -t 47.100.49.228      # c2 轮实现
  recon-go fingerprint -u https://example.com
  recon-go paths -u https://example.com   # c2 轮实现
  recon-go poc -t https://example.com -p pocs/example.yaml  # c2 轮实现
  recon-go llm -d example.com             # 已弃用，Go 版不移植（exit 2）
  recon-go report -t example.com          # c3 轮实现
`

// knownCmds 合法子命令集合（argparse 在解析阶段即拒绝未知子命令，进度事件
// 不发——故 Run 只对集合内子命令包事件流）。与 recon.py:164-187 的子解析器一一对应。
var knownCmds = map[string]bool{
	"all": true, "subdomain": true, "verify": true, "asset": true, "reverse": true,
	"icp": true, "api": true, "fingerprint": true, "paths": true, "jsintel": true,
	"portscan": true, "poc": true, "llm": true, "report": true,
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
	if cmd == "help" { // Go 侧自有帮助子命令：等价 argparse 阶段退出，不发事件
		fmt.Print(helpText)
		return 0
	}
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
		if !parseOrUsage(fs, rest, cmd, "subdomain -d <domain> [--verify]") {
			return 2
		}
		d := pickNonEmpty(*domain, *domainAlias)
		if d == "" {
			return missingArgs(cmd, "subdomain -d <domain> [--verify]")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1 // 对齐 Python：os.makedirs 抛 OSError 未捕获 → exit 1
		}
		subdomain.Run(d, out)
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
		if !parseOrUsage(fs, rest, cmd, "verify -d <domain> [-w workers]") {
			return 2
		}
		d := pickNonEmpty(*domain, *domainAlias)
		if d == "" {
			return missingArgs(cmd, "verify -d <domain> [-w workers]")
		}
		out, err := MakeOutdir(d)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			return 1
		}
		subdomain.RunVerify(out, pickInt(*workers, *workersAlias, 8), true)
		return 0

	case "fingerprint":
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if !parseOrUsage(fs, rest, cmd, "fingerprint -u <url>") {
			return 2
		}
		url := pickNonEmpty(*u, *uAlias)
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

	case "all", "asset", "reverse", "icp", "api", "paths", "jsintel", "portscan", "poc", "report":
		round := 2
		if cmd == "report" {
			round = 3
		}
		fmt.Printf("[*] recon-go: 子命令 %q 将在第 %d/3 轮实现（本轮未移植，exit 2 防止静默走错分支）\n", cmd, round)
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
			HopCheck: func(next string) error {
				_, err := netutil.CheckHTTPURL(next, true)
				return err
			}})
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

func parseOrUsage(fs *flag.FlagSet, args []string, cmd, usage string) bool {
	if err := fs.Parse(args); err != nil {
		fmt.Printf("[!] 参数错误: %v\n  用法: recon-go %s\n", err, usage)
		return false
	}
	return true
}

func missingArgs(cmd, usage string) int {
	fmt.Printf("[!] 缺少必填参数（subcommand=%s）\n  用法: recon-go %s\n", cmd, usage)
	return 2
}

func pickNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pickInt 取非默认值者优先，两个都等于默认则回默认。
func pickInt(a, b, def int) int {
	if a != def {
		return a
	}
	return b
}
