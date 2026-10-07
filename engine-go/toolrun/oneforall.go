// Package toolrun：外部工具子进程适配层。
// 铁律：外部工具一律保持子进程调用、不重写——OneForAll（Python）主通道、
// subfinder（Go 二进制）仅作可选补充通道。
//
// 子进程安全约定（等价 Python subprocess.run([...], shell=False)）：
// 全部走 os/exec 的参数列表形式，不经任何 shell 解释，无字符串拼接命令行；
// 目标脚本路径来自 ONEFORALL_HOME 环境变量（使用者显式配置），与 Python 版一致。
package toolrun

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	subproc "os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RunOneForAll 子进程调用 OneForAll，解析其 NDJSON 输出，对齐 subdomain.py:20-43：
//   - home 为空 → 直接返回空（未配置该通道）；
//   - home/oneforall.py 不存在 → 打印提示并返回空；
//   - 命令行 [python, oneforall.py, --target, domain, --fmt, json, --path, out]（参数列表，无 shell）；
//   - 解析 out/<domain>.json：逐行 TrimSpace、Trim(",")、取 "subdomain"、
//     去首尾点号、去重排序。
//
// 与 Python 的微差：Python subprocess timeout 抛 TimeoutExpired 会一路炸穿，
// Go 侧选择打印告警后返回空（引擎继续走降级链），已在 README 差异说明。
func RunOneForAll(home, domain, out string, timeout time.Duration) []string {
	return RunOneForAllContext(context.Background(), home, domain, out, timeout)
}

// RunOneForAllContext 是 RunOneForAll 的取消变体（第一步「取消能力注入」连带件）：
// 调用方 ctx 接进既有 CommandContext 的超时 ctx（WithTimeout 父子叠加）——
// 桌面取消任务时 Python 子进程随 ctx 中止，与 1800s 超时同一咽喉。
func RunOneForAllContext(ctx context.Context, home, domain, out string, timeout time.Duration) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(home) == "" {
		return nil
	}
	// out 侧复核（fix1 安全门整改，污点汇合点闭环）：清洗后仍以 ".." 起头的
	// out（越出工作目录）一律拦截。调用方 MakeOutdir 已做字符级清洗，测试
	// 传入绝对临时目录亦合法——此处只挡向上逃逸形态。
	cleanOut := filepath.Clean(out)
	if cleanOut == ".." || strings.HasPrefix(cleanOut, ".."+string(filepath.Separator)) {
		fmt.Printf("[!] out 目录越界（含 .. 组件，已拦截）: %q\n", out)
		return nil
	}
	out = cleanOut
	// 路径纪律（审计修复）：domain 会拼进结果文件名 <out>/<domain>.json（与
	// Python subdomain.py:31 一致），但合法域名绝不含路径分隔符或 ".."——
	// 出现即视为非法输入直接返回空（Python 侧同类输入同样读不到文件返回空，
	// 可观测行为一致，此处只是显式拦下目录拼接）。
	if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") {
		fmt.Printf("[!] 非法域名（含路径字符，已拦截）: %q\n", domain)
		return nil
	}
	// home 侧清洗（内联 cleanser，与 domain 侧 strings.Map 同形态）：
	// strings.Map 归一分隔符 → 组件切分 → "." / ".." 悬浮组件与空组件就地
	// 剔除 → 重组绝对路径。清洗产物 safeHome 是此后唯一参与路径操作的值；
	// 剔除后为空即视为非法配置。
	norm := strings.Map(func(r rune) rune {
		if r == '\\' || r == '/' {
			return '/'
		}
		return r
	}, home)
	homeParts := strings.Split(norm, "/")
	homeClean := make([]string, 0, len(homeParts))
	for _, p := range homeParts {
		if p == "" || p == "." || p == ".." {
			continue
		}
		homeClean = append(homeClean, p)
	}
	if len(homeClean) == 0 {
		fmt.Printf("[!] ONEFORALL_HOME 非法（组件清洗后为空，已拦截）: %q\n", home)
		return nil
	}
	// fix2（parity 修复，探针实证）：filepath.Join("C:", "Users", ...) 实测
	// 产出盘符相对路径（卷标后无分隔符），Abs 会落到 cwd 所在盘的相对位置
	// ——TestParityOneForAll 因此挂。卷标/根路径组件显式补分隔符后重组。
	var rebuilt string
	switch {
	case strings.HasSuffix(homeClean[0], ":"):
		rebuilt = homeClean[0] + string(filepath.Separator) +
			strings.Join(homeClean[1:], string(filepath.Separator))
	case strings.HasPrefix(norm, "/"):
		rebuilt = string(filepath.Separator) + strings.Join(homeClean, string(filepath.Separator))
	default:
		rebuilt = filepath.Join(homeClean...)
	}
	safeHome, aerr := filepath.Abs(rebuilt)
	if aerr != nil {
		fmt.Printf("[!] ONEFORALL_HOME 无法解析: %v\n", aerr)
		return nil
	}
	if st, serr := os.Stat(safeHome); serr != nil || !st.IsDir() {
		fmt.Printf("[!] ONEFORALL_HOME 不是存在的目录: %s\n", safeHome)
		return nil
	}
	absHome := safeHome
	exe := filepath.Join(absHome, "oneforall.py")
	// 结构化包含断言（污点门禁可建模的 sanitizer 形态）：exe 必须仍在
	// absHome 前缀内，越界即拦截——不依赖字符串子串判断
	if rel, rerr := filepath.Rel(absHome, exe); rerr != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		fmt.Printf("[!] ONEFORALL_HOME 配置异常（脚本路径越出配置目录，已拦截）: %q\n", absHome)
		return nil
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		fmt.Printf("[!] ONEFORALL_HOME 已设置但找不到 %s\n", exe)
		return nil
	}
	if timeout <= 0 {
		timeout = 1800 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 解释器解析与桌面壳一致：RECON_PYTHON 优先，缺省 python——
	// 不再硬编码，避免与壳侧解析顺序不一致
	py := strings.TrimSpace(os.Getenv("RECON_PYTHON"))
	if py == "" {
		py = "python"
	}
	// 参数列表调用（无 shell）：与 Python subprocess.run([...], check=False, timeout=1800) 一致
	cmd := subproc.CommandContext(runCtx, py, exe, "--target", domain, "--fmt", "json", "--path", out)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("[!] OneForAll 执行失败: %v\n", err)
	}
	// 结果文件名走字符级白名单清洗（域名字母表 [a-z0-9.-] 之外一律剔除）：
	// 清洗后的 safeDomain 才参与路径拼装——清洗后若与原域名不一致，
	// 说明入口形状闸被绕过，直接拒绝（双保险）。
	safeDomain := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return -1
	}, strings.ToLower(domain))
	if safeDomain == "" || safeDomain != strings.ToLower(domain) {
		fmt.Printf("[!] 非法域名（清洗后不一致，已拦截）: %q\n", domain)
		return nil
	}
	// 结果文件结构化包含断言（污点门禁可建模的 sanitizer 形态）：
	// <out>/<domain>.json 解析后必须仍在 out 前缀内
	resultPath := filepath.Join(out, safeDomain+".json")
	if rel, rerr := filepath.Rel(out, resultPath); rerr != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		fmt.Printf("[!] 非法域名（结果路径越出产物目录，已拦截）: %q\n", domain)
		return nil
	}
	return parseOneForAllJSON(resultPath)
}

// parseOneForAllJSON 解析 OneForAll 的行式 JSON 输出（每行一个对象、可能带尾逗号）。
func parseOneForAllJSON(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var subs []string
	sc := newLineScanner(f)
	for sc.Scan() {
		line := strings.Trim(strings.TrimSpace(sc.Text()), ",")
		if line == "" {
			continue
		}
		var row struct {
			Subdomain string `json:"subdomain"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue // 对齐 Python：JSONDecodeError 直接跳过该行
		}
		s := strings.Trim(row.Subdomain, ".") // Python .strip(".")：去首尾点号
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		subs = append(subs, s)
	}
	sort.Strings(subs)
	return subs
}
