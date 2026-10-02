// Package subdomain：子域枚举 + 存活验证，移植 src/modules/subdomain.py。
// 通道链：OneForAll（主，可选）→ subfinder（Go 侧可选补充，存在才用）→
// crt.sh → certspotter；数据源类逻辑（crt.sh/certspotter）是引擎自身逻辑，
// 用 Go 原生 HTTP 实现。测试通过包级 URL 变量注入 httptest stub，零外网。
package subdomain

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/toolrun"
)

// 可注入的数据源 URL 模板（%s = domain）。测试改指向 httptest stub，绝不真连外网。
var (
	CrtShURL       = "https://crt.sh/?q=%%25.%s&output=json"
	CertspotterURL = "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names"
)

// 可注入的通道钩子（测试桩点）；retrySleep 供失败重试测试免等待。
// checkBoundary（fix1 审计 low#7）：通道 URL 请求前边界校验，对齐 Python
// _from_crtsh/_from_certspotter 里请求前的 check_http_url（默认 allow_private=False）。
// 单测桩打在 127.0.0.1 httptest 上，由 withStubs 注入放行（Python 侧 monkeypatch
// fetch 故不受影响）。校验失败走「异常降级」分支：0 次重试直接切下一通道，
// 对齐 Python check_http_url 抛 ValueError 被 run_subdomain 捕获的语义。
var (
	retrySleep    = time.Sleep
	SubfinderFind = toolrun.FindSubfinder
	SubfinderRun  = func(path, domain string) ([]string, error) { return toolrun.RunSubfinder(path, domain, 0) }
	checkBoundary = func(rawURL string) (string, error) { return netutil.CheckHTTPURL(rawURL, false) }
)

// FromCrtSh 证书透明度日志查询，对齐 subdomain.py:46-71：
// 3 次退避重试（sleep 2*i 秒）；彻底失败优雅返回空列表而非抛错；
// name_value 按行拆分 → 去空白 → 小写 → 去左侧 *. → 后缀过滤 → 排序去重。
func FromCrtSh(domain string, tries int) []string {
	if tries <= 0 {
		tries = 3
	}
	url := fmt.Sprintf(CrtShURL, domain)
	if _, err := checkBoundary(url); err != nil {
		// 对齐 Python：check_http_url 抛 ValueError → run_subdomain 打印
		// 「[!] crt.sh 异常」并 0 次重试直接降级 certspotter（不是 3 次退避重试）。
		fmt.Printf("[!] crt.sh 异常: %v\n", err)
		return nil
	}
	var data []struct {
		NameValue string `json:"name_value"`
	}
	found := false
	for i := 1; i <= tries; i++ {
		r := netutil.Fetch(url, netutil.FetchOpt{Timeout: 30 * time.Second, Follow: true})
		if r.OK && r.Status == 200 && r.Body != "" {
			if err := json.Unmarshal([]byte(r.Body), &data); err != nil {
				fmt.Printf("[!] crt.sh 第 %d/%d 次响应解析失败: %v\n", i, tries, err)
			} else {
				found = true
				break
			}
		} else {
			reason := r.Err
			if reason == "" {
				reason = fmt.Sprintf("%d", r.Status)
			}
			fmt.Printf("[!] crt.sh 第 %d/%d 次请求失败: %s\n", i, tries, reason)
		}
		if i < tries {
			retrySleep(time.Duration(2*i) * time.Second)
		}
	}
	if !found {
		fmt.Println("[!] crt.sh 不可用（重试均失败）。可设置 ONEFORALL_HOME 走 OneForAll，或稍后重试")
		return nil
	}
	return collectNames(len(data), func(i int) []string {
		return strings.Split(data[i].NameValue, "\n")
	}, domain)
}

// FromCertspotter 备用证书源，对齐 subdomain.py:74-89：失败返回 error。
func FromCertspotter(domain string) ([]string, error) {
	url := fmt.Sprintf(CertspotterURL, domain)
	if _, err := checkBoundary(url); err != nil {
		// 对齐 Python：check_http_url 抛 ValueError 原样上抛（run_subdomain
		// 捕获后打印「[!] certspotter 也不可用」），不发起 HTTP 请求。
		return nil, err
	}
	r := netutil.Fetch(url, netutil.FetchOpt{Timeout: 30 * time.Second, Follow: true})
	if !(r.OK && r.Status == 200 && r.Body != "") {
		reason := r.Err
		if reason == "" {
			reason = fmt.Sprintf("HTTP %d", r.Status)
		}
		return nil, fmt.Errorf("%s", reason)
	}
	var data []struct {
		DnsNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal([]byte(r.Body), &data); err != nil {
		return nil, err
	}
	return collectNames(len(data), func(i int) []string { return data[i].DnsNames }, domain), nil
}

// collectNames 共用清洗：strip → lower → 去左侧 .* → 剔控制字符 → endswith(domain)
// 过滤 → 排序去重。fix1（对抗 INFO）：crt.sh 返回数据实测内嵌控制字符（\x01\x02），
// 原样进 subdomains.txt 会污染产物与下游解析——剔 <0x20 与 0x7f。剔除时机在
// strip/lower/lstrip 之后，与 Python 侧同步加的清洗位置一致（保证 parity）。
func collectNames(n int, get func(int) []string, domain string) []string {
	suffix := strings.ToLower(domain)
	seen := map[string]bool{}
	var subs []string
	for i := 0; i < n; i++ {
		for _, raw := range get(i) {
			name := strings.ToLower(strings.TrimSpace(raw))
			name = strings.TrimLeft(name, ".*") // Python lstrip("*.")：剥掉左侧所有 . 与 *
			name = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, name)
			if name == "" || !strings.HasSuffix(name, suffix) || seen[name] {
				continue
			}
			seen[name] = true
			subs = append(subs, name)
		}
	}
	sort.Strings(subs)
	return subs
}

// Run 子域枚举主流程，对齐 subdomain.py:92-116 的降级链：
// OneForAll（主）→ crt.sh → certspotter；Go 侧增强：subfinder 作为合并补充
// 通道插在链后（存在才用、失败只告警），不改变 Python 原降级链的触发条件
// （即：OneForAll 无结果时 crt.sh 链照走，subfinder 只做并集补充）。
// 源名与计数打印对齐，结果去重排序后 SafeWrite 到 subdomains.txt。
func Run(domain, out string) []string {
	// 入口污点闸（污点门禁可建模的 sanitizer 形态）：CLI/上层传入的 domain
	// 进入任何通道前做形状白名单——非空、≤253、无路径分隔符/悬浮点组件/
	// 控制字符。非法输入直接返回空（各通道内的同名拦截为第二道纵深）。
	if d := strings.TrimSpace(domain); d == "" || len(d) > 253 ||
		strings.ContainsAny(d, `/\`) || strings.Contains(d, "..") ||
		strings.ContainsFunc(d, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		fmt.Printf("[!] 非法域名（形状校验未过，全部通道拦截）: %q\n", domain)
		return nil
	}
	seen := map[string]bool{}
	var subs []string
	add := func(list []string) {
		for _, s := range list {
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			subs = append(subs, s)
		}
	}

	src := ""
	ofs := toolrun.RunOneForAll(os.Getenv("ONEFORALL_HOME"), domain, out, 0)
	if len(ofs) > 0 {
		src = "OneForAll"
		add(ofs)
	} else {
		// 与 Python 一致：OneForAll 无结果时走证书日志降级链
		if os.Getenv("ONEFORALL_HOME") == "" {
			fmt.Println("[*] 未设置 ONEFORALL_HOME，降级使用证书日志查询")
		}
		src = "crt.sh"
		add(FromCrtSh(domain, 3))
		if len(subs) == 0 {
			fmt.Println("[*] 尝试备用证书源 certspotter")
			cs2, err := FromCertspotter(domain)
			if err != nil {
				fmt.Printf("[!] certspotter 也不可用: %v\n", err)
			} else {
				src = "certspotter"
				add(cs2)
			}
		}
	}
	// Go 侧增强：subfinder 可选合并补充（存在才用，版本 best-effort 记录）。
	if p := SubfinderFind(); p != "" {
		ss, err := SubfinderRun(p, domain)
		if err != nil {
			fmt.Printf("[!] subfinder 通道失败: %v\n", err)
		}
		if len(ss) > 0 {
			add(ss)
			src += "+subfinder"
		}
	}
	sort.Strings(subs) // 多源合并后整体排序（Python 单源本就有序）
	content := strings.Join(subs, "\n")
	if len(subs) > 0 {
		content += "\n"
	}
	path, err := netutil.SafeWrite(out, "subdomains.txt", content)
	if err != nil {
		fmt.Printf("[!] 子域列表写盘失败: %v\n", err)
		path = "-"
	}
	fmt.Printf("[+] 子域枚举完成（%s，%d 个）-> %s\n", src, len(subs), path)
	return subs
}

// marshalPretty 供 verify.go 共用（ensure_ascii=False + indent=2 语义）。
func marshalPretty(v any) string { return jsonx.Pretty(v) }
