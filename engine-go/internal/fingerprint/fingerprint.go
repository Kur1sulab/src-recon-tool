// Package fingerprint：指纹识别，移植 src/modules/fingerprint.py。
// 规则从 fingerprint.py:15-48 逐字移植（28 条，header+body 双通道）；
// body 匹配只认「技术特征」，不匹配自然语言里的框架名词（Python 侧教训）。
package fingerprint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// Rule 单条指纹规则（Name/Where/Pattern/Type 与 Python dict 键一致）。
type Rule struct {
	Name    string
	Where   string // header | body
	Pattern string
	Type    string
}

// Rules 逐字移植 fingerprint.py:15-48 的全部规则（含注释里的语义约束）。
// 已逐条核对 RE2 兼容（无 lookaround/反向引用）。
var Rules = []Rule{
	{"ThinkPHP", "header", `x-powered-by:\s*thinkphp`, "framework"},
	{"ThinkPHP", "body", `thinkphp[_\-/ ]?v?\d+\.\d|think_exception|thinkphp_exception|_method=__construct|/index\.php\?s=/`, "framework"},
	{"Shiro", "header", `rememberme=deleteme`, "framework"},
	{"Spring", "body", `whitelabel error page`, "framework"},
	{"WordPress", "header", `x-powered-by:\s*wordpress|link:.*wp-json`, "cms"},
	{"WordPress", "body", `wp-content/(themes|plugins|uploads)|wp-includes/(js|css)/`, "cms"},
	{"Discuz", "body", `discuz!|forum\.php\?mod=`, "cms"},
	{"Nginx", "header", `nginx|openresty|tengine`, "server"},
	{"Apache", "header", `apache`, "server"},
	{"IIS", "header", `microsoft-iis`, "server"},
	{"Vue", "body", `data-v-[0-9a-f]{8}|__vue__`, "frontend"},
	{"React", "body", `data-reactroot|__react`, "frontend"},
	{"Spring Boot", "header", `x-application-context`, "framework"},
	{"Tomcat", "header", `apache-coyote|tomcat`, "middleware"},
	{"Jetty", "header", `jetty`, "middleware"},
	{"Undertow", "header", `undertow`, "middleware"},
	{"WebLogic", "header", `weblogic`, "middleware"},
	{"Jenkins", "header", `x-jenkins`, "devops"},
	{"Grafana", "body", `"grafanabootdata"|grafana-app|window\.grafana`, "devops"},
	{"Kibana", "body", `kbn-injected-metadata`, "devops"},
	{"Elasticsearch", "body", `"you know, for search"|"cluster_name"\s*:`, "middleware"},
	{"GitLab", "body", `"gitlab_url"|gon\.gitlab|gitlab-ee|gitlab-ce`, "devops"},
	{"Jira", "body", `ajs-version-number|com-atlassian-jira`, "devops"},
	{"phpMyAdmin", "body", `id="pma_username"|pma_password|name="pma_username"`, "tool"},
	{"RabbitMQ", "body", `rabbitmq management`, "middleware"},
	{"Harbor", "body", `harbor-logo|"harbor_version"`, "devops"},
	{"Swagger UI", "body", `swagger-ui\.css|swagger-ui-bundle`, "api"},
	{"Nacos", "body", `console-ui|"nacos"`, "middleware"},
}

// compiled 全规则预编译（包级一次性，RE2 语法）。
var compiled = func() []*regexp.Regexp {
	rs := make([]*regexp.Regexp, len(Rules))
	for i, r := range Rules {
		rs[i] = regexp.MustCompile(r.Pattern)
	}
	return rs
}()

// Hit 命中项，JSON 键对齐 Python {"name","type"}。
type Hit struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// MatchHeaders 对外暴露的匹配入口：按规则顺序匹配，同 Name 只记首次。
// haystacks 必须已按 Python 语义 lowercase。
func MatchHeaders(headerHay, bodyHay string) []Hit {
	hits := []Hit{}
	for i, rule := range Rules {
		hay := bodyHay
		if rule.Where == "header" {
			hay = headerHay
		}
		if !compiled[i].MatchString(hay) {
			continue
		}
		dup := false
		for _, h := range hits {
			if h.Name == rule.Name {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		hits = append(hits, Hit{Name: rule.Name, Type: rule.Type})
	}
	return hits
}

// RunFingerprint 指纹识别主流程，对齐 fingerprint.py:51-75：
// CheckHTTPURL(allowPrivate=true) → Fetch(15s, 300000) → 仅 status==200 匹配 →
// SafeWrite fingerprint.json → 打印命中数与名单。
func RunFingerprint(rawURL, out string) {
	url := ""
	if u, err := netutil.CheckHTTPURL(rawURL, true); err != nil {
		fmt.Printf("[!] 非法探测目标: %v\n", err)
	} else {
		url = u
	}
	var r netutil.Result
	if url != "" {
		r = netutil.Fetch(url, netutil.FetchOpt{Timeout: 15 * time.Second, MaxBytes: 300000, Follow: true})
	}
	var body, headers string
	if r.OK && r.Status == 200 {
		body = strings.ToLower(r.Body)
		var lines []string
		for k, v := range r.Headers {
			lines = append(lines, k+": "+v)
		}
		headers = strings.ToLower(strings.Join(lines, "\n"))
	} else if url != "" {
		reason := r.Err
		if reason == "" {
			reason = strconv.Itoa(r.Status)
		}
		fmt.Printf("[!] 指纹识别请求失败: %s\n", reason)
	}
	hits := MatchHeaders(headers, body)
	path, err := netutil.SafeWrite(out, "fingerprint.json", jsonx.Pretty(hits))
	if err != nil {
		fmt.Printf("[!] fingerprint.json 写盘失败: %v\n", err)
		path = "-"
	}
	names := make([]string, 0, len(hits))
	for _, h := range hits {
		names = append(names, h.Name)
	}
	nameStr := strings.Join(names, "、")
	if nameStr == "" {
		nameStr = "无"
	}
	fmt.Printf("[+] 指纹识别完成（%d 个命中: %s）-> %s\n", len(hits), nameStr, path)
}
