// Package reverseip：IP 反查域名，移植 src/modules/reverse_ip.py。
// 数据源 hackertarget reverseiplookup（免 key、纯文本）。
// 域名正则改造说明：原 Python 正则 `^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$`
// 含 lookaround，RE2 不支持——按等价语义改写为 label 校验函数（每段 1-63 字符、
// 仅 [a-z0-9-]、首尾非 -，整体 ≥2 段），等价性由黄金用例与 parity 钉死。
package reverseip

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// HackertargetBase 可注入（测试打 httptest stub）。
var HackertargetBase = "https://api.hackertarget.com/reverseiplookup/?q=%s"

var retrySleep = time.Sleep

// skipSuffixes 对齐 reverse_ip.py:19（endswith 元组语义：任意后缀命中即跳过）。
var skipSuffixes = []string{".arpa", ".in-addr.arpa", ".ip6.arpa", ".local", ".lan"}

// validDomain 等价 _DOMAIN_RE 的 RE2 兼容改写：
// 整体 ≥2 段；每段 1-63 字符、仅 [a-z0-9-]、首尾非 "-"（即原 (?!-)/(?<!-)）。
func validDomain(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lb := range labels {
		n := len(lb)
		if n < 1 || n > 63 {
			return false
		}
		if lb[0] == '-' || lb[n-1] == '-' {
			return false
		}
		for i := 0; i < n; i++ {
			c := lb[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ParseHackerTarget 解析 hackertarget 纯文本响应（每行一个域名），对齐 reverse_ip.py:22-33：
// strip → lower → rstrip(".")；跳过空行/含空格行/SKIP 后缀；校验通过的排序去重。
func ParseHackerTarget(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		name := strings.TrimRight(strings.ToLower(strings.TrimSpace(line)), ".")
		if name == "" || strings.Contains(name, " ") {
			continue
		}
		skip := false
		for _, suf := range skipSuffixes {
			if strings.HasSuffix(name, suf) {
				skip = true
				break
			}
		}
		if skip || !validDomain(name) {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// fetchText 重试 3 次退避（sleep 2*i），对齐 reverse_ip.py:36-47；全败返回 ""。
func fetchText(u string, tries int) string {
	return fetchTextCtx(context.Background(), u, tries)
}

// fetchTextCtx 是 fetchText 的取消变体（第一步「取消能力注入」①）：请求过
// FetchOpt.Ctx 咽喉，重试循环顶部设检查点——取消立即收敛。旧签名委托本函数，
// 存量测试（含 retrySleep 桩）零改动。
func fetchTextCtx(ctx context.Context, u string, tries int) string {
	if ctx == nil {
		ctx = context.Background()
	}
	if tries <= 0 {
		tries = 3
	}
	last := ""
	for i := 1; i <= tries; i++ {
		if err := ctx.Err(); err != nil { // 取消检查点（第一步①）
			return ""
		}
		r := netutil.Fetch(u, netutil.FetchOpt{Timeout: 25 * time.Second, Follow: true, Ctx: ctx})
		if r.OK && r.Status == 200 && r.Body != "" {
			return r.Body
		}
		last = r.Err
		if last == "" {
			last = fmt.Sprintf("HTTP %d", r.Status)
		}
		fmt.Printf("[!] 反查第 %d/%d 次失败: %s\n", i, tries, last)
		if i < tries {
			retrySleep(time.Duration(2*i) * time.Second)
		}
	}
	fmt.Printf("[!] 反查请求全部失败: %s\n", last)
	return ""
}

// ReverseIP 返回该 IP 关联的域名列表（去重排序），对齐 reverse_ip.py:50-52。
func ReverseIP(ip string) []string {
	return reverseIPCtx(context.Background(), ip)
}

// reverseIPCtx 是 ReverseIP 的取消变体（第一步①）：取数走 fetchTextCtx。
func reverseIPCtx(ctx context.Context, ip string) []string {
	return ParseHackerTarget(fetchTextCtx(ctx, fmt.Sprintf(HackertargetBase, ip), 3))
}

// RunReverse 写 reverse_domains.txt + 打印前 20，对齐 reverse_ip.py:55-68。
func RunReverse(ip, out string) []string {
	return RunReverseContext(context.Background(), ip, out)
}

// RunReverseContext 是 RunReverse 的取消变体（第一步「取消能力注入」①）：
// 入口设检查点，取数走 reverseIPCtx。旧签名委托本函数，cli.go 调用点零改动。
func RunReverseContext(ctx context.Context, ip, out string) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		fmt.Println("[!] IP 反查已取消")
		return nil
	}
	fmt.Printf("[*] IP 反查域名: %s\n", ip)
	doms := reverseIPCtx(ctx, ip)
	content := strings.Join(doms, "\n")
	if len(doms) > 0 {
		content += "\n"
	}
	path, err := netutil.SafeWrite(out, "reverse_domains.txt", content)
	if err != nil {
		fmt.Printf("[!] reverse_domains.txt 写盘失败: %v\n", err)
		path = "-"
	}
	if len(doms) > 0 {
		fmt.Printf("[+] 反查完成，共 %d 个域名 -> %s\n", len(doms), path)
		for i, d := range doms {
			if i >= 20 {
				break
			}
			fmt.Printf("      %s\n", d)
		}
		if len(doms) > 20 {
			fmt.Printf("      ... 另 %d 个\n", len(doms)-20)
		}
	} else {
		fmt.Printf("[!] 未反查到域名（可能该 IP 无 PTR 记录，或数据源限流）-> %s\n", path)
	}
	return doms
}
