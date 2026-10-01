// Package poc：YAML 化 POC 模板引擎（nuclei 风格子集），移植 src/modules/poc_engine.py。
// 首个第三方依赖 gopkg.in/yaml.v3（go.mod 已引入）。
package poc

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// pocUA 对齐 poc_engine.py:27。
const pocUA = "src-recon-tool/1.0 (+authorized-testing-only)"

// Matcher 单条匹配器：status（状态码列表）| contains（响应体关键字列表）。
type Matcher struct {
	Type   string   `yaml:"type" json:"type"`
	Status []int    `yaml:"status" json:"status,omitempty"`
	Words  []string `yaml:"words" json:"words,omitempty"`
}

// Request 单个请求定义。
type Request struct {
	Method    string            `yaml:"method"`
	Path      string            `yaml:"path"`
	Headers   map[string]string `yaml:"headers"`
	Body      string            `yaml:"body"`
	Matchers  []Matcher         `yaml:"matchers"`
	Condition string            `yaml:"condition"`
}

// Template POC 模板。
type Template struct {
	ID       string `yaml:"id"`
	Info     struct {
		Name     string `yaml:"name"`
		Severity string `yaml:"severity"`
	} `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

// MatchOne 对齐 poc_engine.py:30-36：
// status → status ∈ matcher.status；contains → 任一关键字 lower 包含；其余 false。
func MatchOne(m Matcher, status int, body string) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true
			}
		}
		return false
	case "contains":
		low := strings.ToLower(body)
		for _, kw := range m.Words {
			if strings.Contains(low, strings.ToLower(kw)) {
				return true
			}
		}
		return false
	}
	return false
}

// Match 对齐 poc_engine.py:39-43：matchers 空 → false；condition 默认 or。
func Match(matchers []Matcher, status int, body, condition string) bool {
	if len(matchers) == 0 {
		return false
	}
	results := make([]bool, len(matchers))
	for i, m := range matchers {
		results[i] = MatchOne(m, status, body)
	}
	if condition == "and" {
		for _, r := range results {
			if !r {
				return false
			}
		}
		return true
	}
	for _, r := range results {
		if r {
			return true
		}
	}
	return false
}

// RunPOC 执行模板，对齐 poc_engine.py:46-72。返回 hitAny。
func RunPOC(target, pocFile string) bool {
	raw, err := os.ReadFile(pocFile)
	if err != nil {
		fmt.Printf("[!] 模板读取失败: %v\n", err)
		return false
	}
	var tpl Template
	if err := yaml.Unmarshal(raw, &tpl); err != nil {
		fmt.Printf("[!] 模板解析失败: %v\n", err)
		return false
	}
	fmt.Printf("[*] 执行 POC: %s (%s, severity=%s)\n", tpl.ID, tpl.Info.Name, orDefault(tpl.Info.Severity, "info"))
	hitAny := false
	for _, req := range tpl.Requests {
		url := strings.TrimRight(target, "/") + orDefault(req.Path, "/")
		method := strings.ToUpper(orDefault(req.Method, "GET"))
		headers := map[string]string{"User-Agent": pocUA}
		for k, v := range req.Headers { // {**_UA, **req.headers}
			headers[k] = v
		}
		var data []byte
		if req.Body != "" {
			data = []byte(req.Body) // Python: str → .encode()；None → data=None
		}
		r := netutil.Fetch(url, netutil.FetchOpt{
			Timeout: 10 * time.Second, Method: method, Headers: headers, Data: data, Follow: true,
		})
		if r.Status == 0 { // Python status is None → 请求异常
			fmt.Printf("[!] 请求异常 %s: %s\n", url, r.Err)
			continue
		}
		if Match(req.Matchers, r.Status, r.Body, orDefault(req.Condition, "or")) {
			hitAny = true
			fmt.Printf("[+] 命中! %s (HTTP %d)\n", url, r.Status)
			line, _ := json.Marshal(map[string]any{"poc": tpl.ID, "url": url, "status": r.Status})
			fmt.Println(string(line))
		} else {
			fmt.Printf("[-] 未命中 %s (HTTP %d)\n", url, r.Status)
		}
	}
	return hitAny
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}
