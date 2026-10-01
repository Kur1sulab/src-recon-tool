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
	// home 路径纪律（fix1 安全门整改）：环境变量属使用者显式配置，但仍做
	// 规范化校验——拒绝含 ".." 悬浮组件的配置（穿越嫌疑），abs+目录存在性
	// 复核后再拼脚本路径。校验失败打印告警返回空，走降级链。
	if strings.Contains(home, "..") {
		fmt.Printf("[!] ONEFORALL_HOME 非法（含 .. 组件，已拦截）: %q\n", home)
		return nil
	}
	absHome, aerr := filepath.Abs(home)
	if aerr != nil {
		fmt.Printf("[!] ONEFORALL_HOME 无法解析: %v\n", aerr)
		return nil
	}
	if st, serr := os.Stat(absHome); serr != nil || !st.IsDir() {
		fmt.Printf("[!] ONEFORALL_HOME 不是存在的目录: %s\n", absHome)
		return nil
	}
	exe := filepath.Join(absHome, "oneforall.py")
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		fmt.Printf("[!] ONEFORALL_HOME 已设置但找不到 %s\n", exe)
		return nil
	}
if timeout <= 0 {
		timeout = 1800 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// 解释器解析与桌面壳一致：RECON_PYTHON 优先，缺省 python——
	// 不再硬编码，避免与壳侧解析顺序不一致
	py := strings.TrimSpace(os.Getenv("RECON_PYTHON"))
	if py == "" {
		py = "python"
	}
	// 参数列表调用（无 shell）：与 Python subprocess.run([...], check=False, timeout=1800) 一致
	cmd := subproc.CommandContext(ctx, py, exe, "--target", domain, "--fmt", "json", "--path", out)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("[!] OneForAll 执行失败: %v\n", err)
	}
	return parseOneForAllJSON(filepath.Join(out, domain+".json"))
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
