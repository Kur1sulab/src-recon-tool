// Package icp：ICP 备案查询，移植 src/modules/icp.py。
// 数据源 apihz（cn.apihz.cn）；凭据只走环境变量 APIHZ_ID/APIHZ_KEY，
// 源码不写任何可用凭据字面量，未配置即跳过（与 asset 模块行为对齐）。
package icp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// APIHZURL 可注入（测试打 httptest stub）。
var APIHZURL = "https://cn.apihz.cn/api/wangzhan/icp.php"

var retrySleep = time.Sleep

// ParseICP 归一化接口返回，对齐 icp.py:22-41：
//   - 非 JSON 文本 → {"filed":false,"msg":"响应非 JSON"}；
//   - 非 dict（Go 里非 string 且非 map，等价 None/数组等）→ {"filed":false,"msg":"响应格式异常"}；
//   - code==200 且 icp/unit 非空且不含「查询失败」（限频假 200 陷阱）→
//     {filed:true, icp, unit, type, domain, time}；
//   - 其余 → {"filed":false,"msg":msg or 兜底文案}。
func ParseICP(payload any) map[string]any {
	fail := func(msg string) map[string]any { return map[string]any{"filed": false, "msg": msg} }
	var m map[string]any
	switch p := payload.(type) {
	case string:
		if err := json.Unmarshal([]byte(p), &m); err != nil {
			return fail("响应非 JSON")
		}
	case map[string]any:
		m = p
	default:
		return fail("响应格式异常")
	}
	code, _ := m["code"].(float64)
	if int(code) == 200 {
		icp := strings.TrimSpace(str(m["icp"]))
		unit := strings.TrimSpace(str(m["unit"]))
		// apihz 限频时返回 code=200 但字段值为「查询失败」，必须挡掉（icp.py:35 注释）
		if icp == "" || strings.Contains(icp, "查询失败") || strings.Contains(unit, "查询失败") {
			if msg := str(m["msg"]); msg != "" {
				return fail(msg)
			}
			return fail("接口未返回有效备案数据（多为限频，稍后重试）")
		}
		return map[string]any{
			"filed": true, "icp": icp, "unit": unit,
			"type": m["type"], "domain": m["domain"], "time": m["time"],
		}
	}
	if msg := str(m["msg"]); msg != "" {
		return fail(msg)
	}
	return fail("查询失败")
}

// str 等价 Python str(v)：None→""（py 端 (payload.get("icp") or "") 语义），
// 其余按 %v。注意 Python (None or "") 为 ""，非 None 值保持原样。
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// buildAPIHZQuery 构造 apihz 查询参数：url.Values 编码，domain 含 &/# 等
// 特殊字符时不会注入或覆盖其他参数（此前 fmt.Sprintf 直拼已废弃）。
func buildAPIHZQuery(cid, key, domain string) url.Values {
	pv := url.Values{}
	pv.Set("id", cid)
	pv.Set("key", key)
	pv.Set("domain", domain)
	return pv
}

// QueryICP 查询备案，重试 3 次退避，对齐 icp.py:44-57；全败返回 {"filed":false,"msg":...}。
func QueryICP(domain string, tries int) map[string]any {
	cid := os.Getenv("APIHZ_ID")
	key := os.Getenv("APIHZ_KEY")
	if cid == "" || key == "" {
		// 凭据纪律：未配置即跳过，不请求、不降级到任何源码字面量
		return map[string]any{"filed": false,
			"msg": "未配置 APIHZ_ID/APIHZ_KEY，跳过 ICP 查询（设置环境变量后重试）"}
	}
	if tries <= 0 {
		tries = 3
	}
	u := APIHZURL + "?" + buildAPIHZQuery(cid, key, domain).Encode()
	last := ""
	for i := 1; i <= tries; i++ {
		// fix2 P1：id/key 拼在 query 里是 apihz 接口契约，任何 302 跟随都会把
		// 凭据原样转发给跳板——apihz JSON 接口不需要重定向，Follow:false 在
		// 协议层杜绝凭据外送（3xx 停留本机，ok=true/status=302 走失败重试）。
		r := netutil.Fetch(u, netutil.FetchOpt{Timeout: 20 * time.Second, Follow: false})
		if r.OK && r.Status == 200 && r.Body != "" {
			return ParseICP(r.Body)
		}
		last = r.Err
		if last == "" {
			last = fmt.Sprintf("HTTP %d", r.Status)
		}
		fmt.Printf("[!] ICP 查询第 %d/%d 次失败: %s\n", i, tries, last)
		if i < tries {
			retrySleep(time.Duration(2*i) * time.Second)
		}
	}
	return map[string]any{"filed": false, "msg": fmt.Sprintf("请求失败: %s", last)}
}

// RunICP 查询并写 icp_<domain>.json，对齐 icp.py:60-72。
func RunICP(domain, out string) map[string]any {
	fmt.Printf("[*] ICP 备案查询: %s\n", domain)
	res := QueryICP(domain, 3)
	row := map[string]any{"domain": domain}
	for k, v := range res { // {"domain": domain, **res}：res 的同名键覆盖（Python 字面量语义）
		row[k] = v
	}
	path, err := netutil.SafeWrite(out, "icp_"+domain+".json", jsonx.Pretty(row))
	if err != nil {
		fmt.Printf("[!] icp json 写盘失败: %v\n", err)
		path = "-"
	}
	if b, _ := res["filed"].(bool); b {
		fmt.Printf("[+] 备案号: %s\n", res["icp"])
		typ, tim := res["type"], res["time"]
		fmt.Printf("    主办单位: %s    类型: %s    审核: %s\n", res["unit"], dash(typ), dash(tim))
	} else {
		fmt.Printf("[!] 未查询到备案信息（%s）—— 也可能是未备案或接口限频，建议人工复核 beian.miit.gov.cn\n", res["msg"])
	}
	fmt.Printf("    -> %s\n", path)
	return res
}

// dash 等价 Python `v or '-'`（None/空 → "-"）。
func dash(v any) string {
	if s := str(v); s != "" {
		return s
	}
	return "-"
}
