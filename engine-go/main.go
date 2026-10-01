// recon-go：src-recon-tool 的 Go 引擎 CLI。
// 子命令分发表与 Python 入口 src/recon.py:137-212 的 14 个子命令一一对齐；
// 本轮（c1）真实现 subdomain / verify / fingerprint 三个模块，其余注册占位
// 并 exit 2（防止静默走错分支）；llm 模块按铁律不移植、明确弃用。
package main

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

func main() {
	if len(os.Args) < 2 {
		fmt.Print(helpText)
		os.Exit(1)
	}
	os.Exit(dispatch(os.Args[1]))
}

// dispatch 与 recon.py 一一对齐的 14 个子命令。
func dispatch(cmd string) int {
	switch cmd {
	case "subdomain":
		fs := newFlagSet()
		domain := fs.String("d", "", "")
		domainAlias := fs.String("domain", "", "")
		verify := fs.Bool("verify", false, "枚举后立即做存活验证（DNS + HTTP）")
		if !parseOrUsage(fs, os.Args[2:], cmd, "subdomain -d <domain> [--verify]") {
			return 2
		}
		d := pickNonEmpty(*domain, *domainAlias)
		if d == "" {
			return missingArgs(cmd, "subdomain -d <domain> [--verify]")
		}
		out := makeOutdir(d)
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
		if !parseOrUsage(fs, os.Args[2:], cmd, "verify -d <domain> [-w workers]") {
			return 2
		}
		d := pickNonEmpty(*domain, *domainAlias)
		if d == "" {
			return missingArgs(cmd, "verify -d <domain> [-w workers]")
		}
		subdomain.RunVerify(makeOutdir(d), pickInt(*workers, *workersAlias, 8), true)
		return 0

	case "fingerprint":
		fs := newFlagSet()
		u := fs.String("u", "", "")
		uAlias := fs.String("url", "", "")
		if !parseOrUsage(fs, os.Args[2:], cmd, "fingerprint -u <url>") {
			return 2
		}
		url := pickNonEmpty(*u, *uAlias)
		if url == "" {
			return missingArgs(cmd, "fingerprint -u <url>")
		}
		fingerprint.RunFingerprint(url, makeOutdir(url))
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

// isIP 等价 recon.py:30 is_ip（ipaddress.ip_address 可解析即真）。
func isIP(s string) bool { return net.ParseIP(strings.TrimSpace(s)) != nil }

// makeOutdir 等价 recon.py:38-41：out/<target 清洗>，://、/、: 一律换 _。
func makeOutdir(target string) string {
	out := "out" + string(os.PathSeparator) +
		strings.NewReplacer("://", "_", "/", "_", ":", "_").Replace(target)
	_ = os.MkdirAll(out, 0o755)
	return out
}

// pickBase 等价 recon.py:44-63：优先 https，status<500 即用，失败退 http。
// 授权测试允许内网目标，故显式 allowPrivate=true 放行私网（c2 轮 all 命令使用）。
func pickBase(host string) string {
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host
		checked, err := netutil.CheckHTTPURL(url, true)
		if err != nil {
			continue
		}
		r := netutil.Fetch(checked, netutil.FetchOpt{Timeout: 10 * time.Second, Follow: true})
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
