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
	subproc "os/exec"
	"os"
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
	// 路径纪律（审计修复）：domain 会拼进结果文件名 <out>/<domain>.json（与
	// Python subdomain.py:31 一致），但合法域名绝不含路径分隔符或 ".."——
	// 出现即视为非法输入直接返回空（Python 侧同类输入同样读不到文件返回空，
	// 可观测行为一致，此处只是显式拦下目录拼接）。
	if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") {
		fmt.Printf("[!] 非法域名（含路径字符，已拦截）: %q\n", domain)
		return nil
	}
	exe := filepath.Join(home, "oneforall.py")
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		fmt.Printf("[!] ONEFORALL_HOME 已设置但找不到 %s\n", exe)
		return nil
	}
	if timeout <= 0 {
		timeout = 1800 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// 参数列表调用（无 shell）：与 Python subprocess.run([...], check=False, timeout=1800) 一致
	cmd := subproc.CommandContext(ctx, "python", exe, "--target", domain, "--fmt", "json", "--path", out)
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
