// dnsrec.go — DNS 记录检查（报告 §5.6）：标准库直出 8 类
// （A/AAAA/CNAME/MX/NS/TXT/SRV/PTR），worker 8、单查询 3s；SOA/CAA/DS/DNSKEY
// 走 DoH JSON API（dns.google/resolve 免 key，--doh 默认关，方案 a——
// go doc net.Resolver 无 LookupSOA/CAA/DS/DNSKEY，2026-10-05 实证；
// 不引 miekg/dns，go.mod 零新增 require）；与 verify 已解析 A 记录去重
// （Options.KnownA 传入即复用，不重复查询）。
package baseline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// DoHBase DoH JSON API（免 key；可注入换靶）。
var DoHBase = "https://dns.google/resolve"

// dohFetch 可注入（测试打 httptest stub）；生产走 netutil.Fetch。
var dohFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
	r := netutil.Fetch(rawURL, netutil.FetchOpt{Timeout: timeout})
	if !r.OK {
		return nil, fmt.Errorf("DoH 请求失败: %s", r.Err)
	}
	if r.Status >= 400 {
		return nil, fmt.Errorf("DoH HTTP %d", r.Status)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		return nil, fmt.Errorf("DoH 响应非 JSON: %w", err)
	}
	return m, nil
}

// DoH type 值（RFC 1035/3597 编号）。
const (
	dohTypeSOA    = 6
	dohTypeDS     = 43
	dohTypeDNSKEY = 48
	dohTypeCAA    = 257
)

// dohQuery 单类型 DoH 查询，返回 Answer.data 列表。
func dohQuery(name string, typ int) ([]string, error) {
	u := fmt.Sprintf("%s?name=%s&type=%d", DoHBase, url.QueryEscape(name), typ)
	m, err := dohFetch(u, 8*time.Second)
	if err != nil {
		return nil, err
	}
	// F5（终修轮）：Status 在场但非数值按查询失败处理——此前类型断言失败
	// 被静默跳过，敌意 DoH 源可以字符串 Status（"SERVFAIL"）逃过 DNSSEC
	// 判定、投喂伪造 DS/DNSKEY 触发「疑似启用 DNSSEC」误报。
	if raw, ok := m["Status"]; ok {
		st, isNum := raw.(float64)
		if !isNum || int(st) != 0 {
			return nil, fmt.Errorf("DoH Status 异常: %v", raw)
		}
	}
	answers, _ := m["Answer"].([]any)
	out := []string{}
	for _, a := range answers {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if d, ok := am["data"].(string); ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// srvProbeList 常见 SRV 服务名（命中与否如实记录，不做筛选推断）。
var srvProbeList = []struct{ Service, Proto string }{
	{"sip", "tcp"}, {"sip", "udp"},
	{"xmpp-client", "tcp"}, {"xmpp-server", "tcp"},
	{"autodiscover", "tcp"},
}

// srvResult LookupSRV 双返回值的装箱形态。
type srvResult struct {
	Canon string
	Recs  []*netSRV
}

// dnsJob 单条查询任务（key 供结果归集）。
type dnsJob struct {
	key string
	fn  func() (any, error)
}

// dnsJobResult 单条查询结果。
type dnsJobResult struct {
	key string
	val any
	err error
}

// runDNSJobs worker 池（§5.6：worker 8）。
func runDNSJobs(jobs []dnsJob, workers int) map[string]dnsJobResult {
	if workers <= 0 {
		workers = 8
	}
	jch := make(chan dnsJob)
	out := make(chan dnsJobResult, len(jobs))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jch {
				v, err := j.fn()
				out <- dnsJobResult{key: j.key, val: v, err: err}
			}
		}()
	}
	for _, j := range jobs {
		jch <- j
	}
	close(jch)
	go func() { wg.Wait(); close(out) }()
	res := map[string]dnsJobResult{}
	for r := range out {
		res[r.key] = r
	}
	return res
}

// dnsErrClassify 查询失败分类（§5.6 验收：NXDOMAIN/超时等类型分字段记录）。
func dnsErrClassify(err error) string {
	if err == nil {
		return ""
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return "NXDOMAIN"
		case de.IsTimeout:
			return "查询超时"
		}
		return de.Err
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout") {
		return "查询超时"
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// RunDNSRec DNS 记录检查主流程。逐字段失败记录进 data.errors（不置 Error——
// 个别记录缺失/失败是数据不是模块故障，聚合按 done 收尾）。
func RunDNSRec(o Options) Result {
	res := NewResult(CheckDNSRec, o.Domain, "")
	d := o.Domain

	jobs := []dnsJob{}
	// A：verify 已解析映射在场则复用不查询（§5.6 合并语义）
	if ips, ok := o.KnownA[d]; ok {
		jobs = append(jobs, dnsJob{"a", func() (any, error) { return ips, nil }})
	} else {
		jobs = append(jobs, dnsJob{"a", func() (any, error) {
			return qDNS(func(ctx context.Context) ([]string, error) { return dns.LookupHost(ctx, d) })
		}})
	}
	jobs = append(jobs,
		dnsJob{"aaaa", func() (any, error) {
			return qDNS(func(ctx context.Context) ([]netIPAddr, error) { return dns.LookupIP(ctx, "ip6", d) })
		}},
		dnsJob{"cname", func() (any, error) {
			return qDNS(func(ctx context.Context) (string, error) { return dns.LookupCNAME(ctx, d) })
		}},
		dnsJob{"mx", func() (any, error) {
			return qDNS(func(ctx context.Context) ([]*netMX, error) { return dns.LookupMX(ctx, d) })
		}},
		dnsJob{"ns", func() (any, error) {
			return qDNS(func(ctx context.Context) ([]*netNS, error) { return dns.LookupNS(ctx, d) })
		}},
		dnsJob{"txt", func() (any, error) {
			return qDNS(func(ctx context.Context) ([]string, error) { return dns.LookupTXT(ctx, d) })
		}},
	)
	for _, s := range srvProbeList {
		svc, proto := s.Service, s.Proto
		jobs = append(jobs, dnsJob{"srv:" + svc + "." + proto, func() (any, error) {
			return qDNS(func(ctx context.Context) (any, error) {
				canon, recs, err := dns.LookupSRV(ctx, svc, proto, d)
				return srvResult{Canon: canon, Recs: recs}, err
			})
		}})
	}
	results := runDNSJobs(jobs, 8)

	// 归集（JSON 友好形态；列表空时给 [] 非 null）
	aHosts := []string{}
	if r := results["a"]; r.err == nil {
		if l, ok := r.val.([]string); ok {
			aHosts = l
		}
	}
	aaaaList := []string{}
	if r := results["aaaa"]; r.err == nil {
		if l, ok := r.val.([]netIPAddr); ok {
			for _, a := range l {
				aaaaList = append(aaaaList, a.IP.String())
			}
		}
	}
	cname := ""
	if r := results["cname"]; r.err == nil {
		if s, ok := r.val.(string); ok {
			cname = strings.TrimSuffix(s, ".")
		}
	}
	mxRows := []map[string]any{}
	if r := results["mx"]; r.err == nil {
		if l, ok := r.val.([]*netMX); ok {
			for _, m := range l {
				mxRows = append(mxRows, map[string]any{"host": strings.TrimSuffix(m.Host, "."), "pref": m.Pref})
			}
		}
	}
	nsList := []string{}
	if r := results["ns"]; r.err == nil {
		if l, ok := r.val.([]*netNS); ok {
			for _, n := range l {
				nsList = append(nsList, strings.TrimSuffix(n.Host, "."))
			}
		}
	}
	txtList := []string{}
	if r := results["txt"]; r.err == nil {
		if l, ok := r.val.([]string); ok {
			txtList = l
		}
	}
	srvRows := []map[string]any{}
	for _, s := range srvProbeList {
		r, ok := results["srv:"+s.Service+"."+s.Proto]
		if !ok || r.err != nil {
			continue
		}
		if sr, ok := r.val.(srvResult); ok {
			for _, rec := range sr.Recs {
				srvRows = append(srvRows, map[string]any{
					"service": s.Service, "proto": s.Proto,
					"target": strings.TrimSuffix(rec.Target, "."), "port": rec.Port,
				})
			}
		}
	}

	// PTR：对 A 记录 IP 反查（cap 3，避免对每个 IP 追问）
	ptrMap := map[string]any{}
	ptrErrs := map[string]string{}
	var ptrJobs []dnsJob
	for i, ip := range aHosts {
		if i >= 3 {
			break
		}
		ip := ip
		ptrJobs = append(ptrJobs, dnsJob{"ptr|" + ip, func() (any, error) {
			return qDNS(func(ctx context.Context) ([]string, error) { return dns.LookupAddr(ctx, ip) })
		}})
	}
	ptrResults := runDNSJobs(ptrJobs, 3)
	for _, ip := range aHosts {
		if r, ok := ptrResults["ptr|"+ip]; ok {
			if r.err != nil {
				ptrErrs[ip] = dnsErrClassify(r.err)
				continue
			}
			if l, ok := r.val.([]string); ok {
				names := []string{}
				for _, n := range l {
					names = append(names, strings.TrimSuffix(n, "."))
				}
				ptrMap[ip] = names
			}
		}
	}

	// 逐字段错误记录（§5.6 验收：失败类型分字段记录）
	errs := map[string]string{}
	for key, r := range results {
		if r.err != nil {
			errs[key] = dnsErrClassify(r.err)
		}
	}
	if len(ptrErrs) > 0 {
		for ip, e := range ptrErrs {
			errs["ptr|"+ip] = e
		}
	}

	res.Data["a"] = aHosts
	res.Data["aaaa"] = aaaaList
	res.Data["cname"] = cname
	res.Data["mx"] = mxRows
	res.Data["ns"] = nsList
	res.Data["txt"] = txtList
	res.Data["srv"] = srvRows
	res.Data["ptr"] = ptrMap
	res.Data["errors"] = errs

	// SOA/CAA/DS/DNSKEY：--doh 关 → 明示「未查」，不编造空记录（§5.6 验收）
	dohMark := func(v []string, err error) any {
		if err != nil {
			return "查询失败（" + err.Error() + "）"
		}
		if len(v) == 0 {
			return "无记录"
		}
		return v
	}
	if !o.DoH {
		for _, k := range []string{"soa", "caa", "ds", "dnskey"} {
			res.Data[k] = "未查（--doh 未开）"
		}
		res.Data["dnssec"] = "未查（--doh 未开）"
	} else {
		soa, soaErr := dohQuery(d, dohTypeSOA)
		caa, caaErr := dohQuery(d, dohTypeCAA)
		ds, dsErr := dohQuery(d, dohTypeDS)
		dk, dkErr := dohQuery(d, dohTypeDNSKEY)
		res.Data["soa"] = dohMark(soa, soaErr)
		res.Data["caa"] = dohMark(caa, caaErr)
		res.Data["ds"] = dohMark(ds, dsErr)
		res.Data["dnskey"] = dohMark(dk, dkErr)
		if (dsErr == nil && len(ds) > 0) || (dkErr == nil && len(dk) > 0) {
			res.Data["dnssec"] = "发现 DS/DNSKEY（疑似启用 DNSSEC）"
			res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: "域名疑似启用 DNSSEC（DS/DNSKEY 在场）"})
		} else {
			res.Data["dnssec"] = "未发现 DS/DNSKEY"
		}
	}

	if len(aHosts) == 0 {
		res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: "域名无 A 记录（未解析或仅 IPv6）"})
	}
	if len(txtList) > 0 {
		res.Data["txt_sample"] = txtList
	}
	res.Data["summary"] = []string{
		fmt.Sprintf("A %d 条 / AAAA %d 条 / MX %d 条 / NS %d 条", len(aHosts), len(aaaaList), len(mxRows), len(nsList)),
		fmt.Sprintf("TXT %d 条 / SRV 命中 %d 条 / PTR %d 个 IP", len(txtList), len(srvRows), len(ptrMap)),
	}
	if cname != "" {
		res.Data["summary"] = append(res.Data["summary"].([]string), "CNAME → "+cname)
	}
	res.Conclusion = Conclusion{Level: LevelOK, Text: fmt.Sprintf(
		"A %d / AAAA %d / MX %d / NS %d / TXT %d / SRV %d（失败字段 %d 个）",
		len(aHosts), len(aaaaList), len(mxRows), len(nsList), len(txtList), len(srvRows), len(errs))}
	return res
}
