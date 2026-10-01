// Package asset：资产测绘（FOFA / Hunter API），移植 src/modules/asset.py。
// key 一律走环境变量（FOFA_EMAIL+FOFA_KEY / HUNTER_KEY），绝不硬编码；
// 两者都未配置时跳过并提示，不阻断流水线。
// 测试注入点：FofaBase/HunterBase 指向 httptest stub；checkURL 可放行私网
// （生产默认 CheckHTTPURL(u,false)，对齐 asset.py:30/47 默认阻断私网）。
package asset

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// 可注入的数据源 URL 模板（%s = url.Values.Encode() 后的 query）。
var (
	FofaBase   = "https://fofa.info/api/v1/search/all?%s"
	HunterBase = "https://hunter.qianxin.com/openApi/search?%s"
	// checkURL 生产默认阻断私网（对齐 asset.py:30/47）；测试替换为放行版打 httptest。
	checkURL = func(u string) (string, error) { return netutil.CheckHTTPURL(u, false) }
)

// pyStr 等价 Python f"{v}" 的字符串化：None→"None"，其余按 %v。
func pyStr(v any) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%v", v)
}

// ParseFofaResults 解析 FOFA results（[[host,ip,port,protocol],...]）→ "host|ip|port|protocol" 行。
// 对齐 asset.py:39 推导式（含 None→"None" 的 Python 字符串化语义）。
func ParseFofaResults(results [][]any) []string {
	out := make([]string, 0, len(results))
	for _, row := range results {
		cells := make([]string, 4)
		for i := 0; i < 4; i++ {
			if i < len(row) {
				cells[i] = pyStr(row[i])
			}
		}
		out = append(out, strings.Join(cells, "|"))
	}
	return out
}

// ParseHunterArr 解析 Hunter data.arr（[{domain,ip,port,protocol},...]）→ 同格式行。
// 对齐 asset.py:57-58（缺键取 ""，Python a.get('domain','')）。
func ParseHunterArr(arr []map[string]any) []string {
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		get := func(k string) string {
			if v, ok := a[k]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}
		out = append(out, get("domain")+"|"+get("ip")+"|"+get("port")+"|"+get("protocol"))
	}
	return out
}

// fofaFetch fetch+解析（URL 由调用方校验后传入），对齐 asset.py:31-39。
func fofaFetch(u string) []string {
	r := netutil.Fetch(u, netutil.FetchOpt{Timeout: 20 * time.Second})
	if !(r.OK && r.Status == 200 && r.Body != "") {
		reason := r.Err
		if reason == "" {
			reason = fmt.Sprintf("%d", r.Status)
		}
		fmt.Printf("[!] FOFA 请求失败: %s\n", reason)
		return nil
	}
	var data struct {
		Error   bool   `json:"error"`
		Errmsg  string `json:"errmsg"`
		Results [][]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(r.Body), &data); err != nil {
		fmt.Printf("[!] FOFA 请求失败: %v\n", err)
		return nil
	}
	if data.Error {
		fmt.Printf("[!] FOFA 返回错误: %s\n", data.Errmsg)
		return nil
	}
	return ParseFofaResults(data.Results)
}

// hunterFetch fetch+解析（URL 由调用方校验后传入），对齐 asset.py:49-58。
func hunterFetch(u string) []string {
	r := netutil.Fetch(u, netutil.FetchOpt{Timeout: 20 * time.Second})
	if !(r.OK && r.Status == 200 && r.Body != "") {
		reason := r.Err
		if reason == "" {
			reason = fmt.Sprintf("%d", r.Status)
		}
		fmt.Printf("[!] Hunter 请求失败: %s\n", reason)
		return nil
	}
	var data struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Arr []map[string]any `json:"arr"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(r.Body), &data); err != nil {
		fmt.Printf("[!] Hunter 请求失败: %v\n", err)
		return nil
	}
	if data.Code != 200 {
		fmt.Printf("[!] Hunter 返回错误: %s\n", data.Message)
		return nil
	}
	return ParseHunterArr(data.Data.Arr)
}

// RunAsset 资产测绘主流程，对齐 asset.py:61-81：
// FOFA → Hunter → 保序去重（dict.fromkeys 语义）写 assets.txt。
func RunAsset(domain, out string) {
	var items []string
	var sources []string
	if email, key := os.Getenv("FOFA_EMAIL"), os.Getenv("FOFA_KEY"); email != "" && key != "" {
		q := base64.StdEncoding.EncodeToString([]byte(`domain="` + domain + `"`))
		pv := url.Values{}
		pv.Set("qbase64", q)
		pv.Set("email", email)
		pv.Set("key", key)
		pv.Set("size", "100")
		pv.Set("fields", "host,ip,port,protocol")
		func() {
			u, err := checkURL(fmt.Sprintf(FofaBase, pv.Encode()))
			if err != nil {
				fmt.Printf("[!] FOFA 查询失败: %v\n", err)
				return
			}
			defer func() { // 解析异常不炸穿（对齐外层 try/except）
				if r := recover(); r != nil {
					fmt.Printf("[!] FOFA 查询失败: %v\n", r)
				}
			}()
			if fofa := fofaFetch(u); len(fofa) > 0 {
				items = append(items, fofa...)
				sources = append(sources, fmt.Sprintf("FOFA %d 条", len(fofa)))
			}
		}()
	}
	if key := os.Getenv("HUNTER_KEY"); key != "" {
		q := base64.StdEncoding.EncodeToString([]byte(`domain="` + domain + `"`))
		pv := url.Values{}
		pv.Set("api-key", key)
		pv.Set("search", q)
		pv.Set("page", "1")
		pv.Set("page_size", "100")
		func() {
			u, err := checkURL(fmt.Sprintf(HunterBase, pv.Encode()))
			if err != nil {
				fmt.Printf("[!] Hunter 查询失败: %v\n", err)
				return
			}
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("[!] Hunter 查询失败: %v\n", r)
				}
			}()
			if hunter := hunterFetch(u); len(hunter) > 0 {
				items = append(items, hunter...)
				sources = append(sources, fmt.Sprintf("Hunter %d 条", len(hunter)))
			}
		}()
	}
	if len(sources) == 0 {
		fmt.Println("[!] 未配置 FOFA_EMAIL/FOFA_KEY 或 HUNTER_KEY，跳过资产测绘")
	}
	seen := map[string]bool{}
	var uniq []string
	for _, it := range items { // dict.fromkeys：保序去重
		if seen[it] {
			continue
		}
		seen[it] = true
		uniq = append(uniq, it)
	}
	var sb strings.Builder
	for _, it := range uniq {
		sb.WriteString(it + "\n")
	}
	path, err := netutil.SafeWrite(out, "assets.txt", sb.String())
	if err != nil {
		fmt.Printf("[!] assets.txt 写盘失败: %v\n", err)
		path = "-"
	}
	src := "0 条"
	if len(sources) > 0 {
		src = strings.Join(sources, "+")
	}
	fmt.Printf("[+] 资产测绘完成（%s）-> %s\n", src, path)
}
