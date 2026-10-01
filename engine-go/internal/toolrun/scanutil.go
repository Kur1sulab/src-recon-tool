package toolrun

import (
	"bufio"
	"encoding/json"
	"os"
	subproc "os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// newLineScanner 供各解析器共用的行扫描器（放大缓冲，防长行截断）。
func newLineScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return sc
}

// FindSubfinder 探测本机 subfinder 可执行文件：
// 先找 <cwd>/tools/bin/subfinder.exe（仓库约定目录），再找 PATH。
// 找不到返回 ""——可选通道语义：缺席不报错、不影响主降级链。
func FindSubfinder() string {
	cand := filepath.Join("tools", "bin", "subfinder.exe")
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return cand
	}
	if p, err := subproc.LookPath("subfinder"); err == nil {
		return p
	}
	return ""
}

// RunSubfinder 子进程调用 subfinder（-d domain，JSON 输出到临时文件），
// 返回去重排序的子域列表；并把版本号追加记录到 tools/bin/VERSIONS.md
// （best-effort，失败不影响主流程）。参数列表调用，不经 shell。
func RunSubfinder(path, domain string, timeout time.Duration) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = 600 * time.Second
	}
	tmp, err := os.CreateTemp("", "subfinder-*.jsonl")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)

	cmd := subproc.Command(path, "-d", domain, "-oJ", tmpName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// subfinder 对无结果也可能非零退出：只要临时文件有内容就继续解析
		if st, statErr := os.Stat(tmpName); statErr != nil || st.Size() == 0 {
			return nil, err
		}
		_ = out
	}
	subs := parseSubfinderJSON(tmpName)
	if len(subs) == 0 {
		// 兜底：把 stdout 按行当普通子域列表
		subs = parsePlainLines(string(out))
	}
	recordVersion(path)
	sort.Strings(subs)
	return subs, nil
}

func parseSubfinderJSON(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var subs []string
	sc := newLineScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		s := strings.Trim(strings.TrimSpace(row.Host), ".")
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		subs = append(subs, s)
	}
	return subs
}

func parsePlainLines(text string) []string {
	seen := map[string]bool{}
	var subs []string
	for _, l := range strings.Split(text, "\n") {
		s := strings.Trim(strings.TrimSpace(l), ".")
		if s == "" || seen[s] || strings.ContainsAny(s, " {}\"") {
			continue
		}
		seen[s] = true
		subs = append(subs, s)
	}
	return subs
}

// recordVersion 把 subfinder 版本追加到 tools/bin/VERSIONS.md（best-effort）。
func recordVersion(path string) {
	vb, err := subproc.Command(path, "--version").CombinedOutput()
	if err != nil && len(vb) == 0 {
		return
	}
	dir := filepath.Join("tools", "bin")
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "VERSIONS.md"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write([]byte("- subfinder " + strings.TrimSpace(string(vb)) + " (" + path + ")\n"))
}
