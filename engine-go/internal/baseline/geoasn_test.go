package baseline

// geoasn_test.go — IP 归属/ASN 检查（§5.8）验收：
//   1. 三源响应 fixture 解析映射断言（三家 JSON 字段名不同）。
//   2. 第一源注入失败 → 自动降级第二源。
//   4. 限速生效：连续查询间隔 ≥1 秒（计时断言）。
//   + 假 200 限频页防御、多源分歧 conflict、无 IP 入参失败态。
// 全部离线（geoFetch 注入桩）。

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ipwho.is / ip-api.com / geojs 三家字段名各异的 fixture（§5.8）。
var geoFixtures = map[string]map[string]any{
	"ipwho.is": {"ip": "1.1.1.1", "success": true, "country": "Australia", "region": "Queensland",
		"connection": map[string]any{"asn": float64(13335), "isp": "Cloudflare, Inc", "org": "APNIC-Cloudflare"}},
	"ip-api.com": {"status": "success", "country": "Australia", "regionName": "Queensland",
		"isp": "Cloudflare, Inc", "org": "APNIC", "as": "AS13335 Cloudflare, Inc.", "asname": "CLOUDFLARENET"},
	"geojs": {"country": "Australia", "region": "Queensland",
		"organization_name": "Cloudflare, Inc.", "asn": "13335", "asn_organization": "CLOUDFLARENET"},
}

func TestGeoParsers(t *testing.T) {
	g := parseGeoInfo("ipwho.is", geoFixtures["ipwho.is"])
	if g.Country != "Australia" || g.Region != "Queensland" || g.ISP != "Cloudflare, Inc" ||
		g.AS != "AS13335" || g.ASName != "APNIC-Cloudflare" {
		t.Errorf("ipwho.is 映射 = %+v", g)
	}
	g = parseGeoInfo("ip-api.com", geoFixtures["ip-api.com"])
	if g.Country != "Australia" || g.Region != "Queensland" || g.AS != "AS13335 Cloudflare, Inc." || g.ASName != "CLOUDFLARENET" {
		t.Errorf("ip-api 映射 = %+v", g)
	}
	g = parseGeoInfo("geojs", geoFixtures["geojs"])
	if g.Country != "Australia" || g.ISP != "Cloudflare, Inc." || g.AS != "AS13335" || g.ASName != "CLOUDFLARENET" {
		t.Errorf("geojs 映射 = %+v", g)
	}
}

// geoStub 按 URL 路由应答的桩（记录命中源与调用次数）。
type geoStub struct {
	handler func(url string) (map[string]any, error)
	urls    []string
}

func (s *geoStub) fetch(rawURL string, _ time.Duration) (map[string]any, error) {
	s.urls = append(s.urls, rawURL)
	return s.handler(rawURL)
}

func sourceOf(url string) string {
	for _, src := range GeoSources {
		if strings.HasPrefix(url, src.urlBase) {
			return src.name
		}
	}
	return "?"
}

func TestGeoFallback(t *testing.T) {
	// 第一源（ipwho.is）注入失败 → 自动降级第二源（ip-api.com）
	stub := &geoStub{handler: func(url string) (map[string]any, error) {
		if sourceOf(url) == "ipwho.is" {
			return nil, errors.New("connection refused")
		}
		return geoFixtures["ip-api.com"], nil
	}}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch, geoSleep = stub.fetch, func(time.Duration) {} // 提速
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	res := RunGeoASN(Options{IPs: []string{"1.1.1.1"}, Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("降级用例不应失败: %s", res.Error)
	}
	rows := res.Data["ips"].([]geoIPRow)
	if rows[0].Source != "ip-api.com" {
		t.Errorf("应落第二源: %+v", rows[0])
	}
	if len(stub.urls) != 2 { // 1 失败 + 1 成功（首源成功才 cross-check 第二个）
		t.Errorf("调用序 = %v", stub.urls)
	}
}

func TestGeoFake200Defense(t *testing.T) {
	// 假 200 限频页：HTTP 200 但 body 是错误/限额关键字 → 按失败降级
	stub := &geoStub{handler: func(url string) (map[string]any, error) {
		if sourceOf(url) == "ipwho.is" {
			return map[string]any{"success": false, "message": "quota exceeded"}, nil
		}
		return geoFixtures["ip-api.com"], nil
	}}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch, geoSleep = stub.fetch, func(time.Duration) {}
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	res := RunGeoASN(Options{IPs: []string{"1.1.1.1"}, Logf: quietLogf})
	rows := res.Data["ips"].([]geoIPRow)
	if rows[0].Source != "ip-api.com" {
		t.Errorf("假 200 应触发降级: %+v", rows[0])
	}
}

func TestGeoConflict(t *testing.T) {
	// 两源成功且国家不一致 → 并列输出 + conflict 标记
	stub := &geoStub{handler: func(url string) (map[string]any, error) {
		switch sourceOf(url) {
		case "ipwho.is":
			return geoFixtures["ipwho.is"], nil
		case "ip-api.com":
			m := map[string]any{}
			for k, v := range geoFixtures["ip-api.com"] {
				m[k] = v
			}
			m["country"] = "United States" // 分歧
			return m, nil
		}
		return nil, errors.New("unused")
	}}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch, geoSleep = stub.fetch, func(time.Duration) {}
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	res := RunGeoASN(Options{IPs: []string{"1.1.1.1"}, Logf: quietLogf})
	rows := res.Data["ips"].([]geoIPRow)
	if !rows[0].Conflict || rows[0].Alt == nil || rows[0].Alt.Country != "United States" {
		t.Errorf("应标 conflict 并列输出: %+v", rows[0])
	}
	found := false
	for _, r := range res.Risks {
		if strings.Contains(r.Title, "分歧") {
			found = true
		}
	}
	if !found {
		t.Errorf("应有分歧风险条目: %+v", res.Risks)
	}
}

func TestGeoRateLimit(t *testing.T) {
	// 验收 4：连续查询间隔 ≥1 秒（真实计时，2 个 IP → ≥1s 间隔）
	stub := &geoStub{handler: func(string) (map[string]any, error) { return geoFixtures["geojs"], nil }}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch = stub.fetch
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	start := time.Now()
	res := RunGeoASN(Options{IPs: []string{"1.1.1.1", "8.8.8.8"}, Logf: quietLogf})
	elapsed := time.Since(start)
	if res.Error != "" {
		t.Fatalf("不应失败: %s", res.Error)
	}
	if elapsed < 1*time.Second {
		t.Errorf("限速 1 QPS：2 次查询应 ≥1s, 实际 %v", elapsed)
	}
}

func TestGeoSleepCallCount(t *testing.T) {
	// 机制复核：1 QPS 不变量 = n 次外联调用恰 n-1 次限速（首查询不限速）；
	// 2 IP × （首源 + 交叉源）= 4 次调用 → 3 次限速
	stub := &geoStub{handler: func(string) (map[string]any, error) { return geoFixtures["geojs"], nil }}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch = stub.fetch
	sleeps := 0
	geoSleep = func(time.Duration) { sleeps++ }
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	RunGeoASN(Options{IPs: []string{"1.1.1.1", "8.8.8.8"}, Logf: quietLogf})
	if sleeps != len(stub.urls)-1 {
		t.Errorf("限速调用数应 = 外联数-1（1 QPS）, 得 sleeps=%d calls=%d", sleeps, len(stub.urls))
	}
}

func TestGeoNoIPs(t *testing.T) {
	old := dns
	dns = &allFailDNS{}
	t.Cleanup(func() { dns = old })
	oldFetch, oldSleep := geoFetch, geoSleep
	geoSleep = func(time.Duration) {}
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	res := RunGeoASN(Options{Domain: "unresolvable.test", Logf: quietLogf})
	if res.Error == "" || !strings.Contains(res.Error, "无可用 IP") {
		t.Errorf("无 IP 应失败态: %+v", res)
	}
}

func TestGeoAllSourcesFail(t *testing.T) {
	stub := &geoStub{handler: func(string) (map[string]any, error) { return nil, errors.New("all down") }}
	oldFetch, oldSleep := geoFetch, geoSleep
	geoFetch, geoSleep = stub.fetch, func(time.Duration) {}
	t.Cleanup(func() { geoFetch, geoSleep = oldFetch, oldSleep })

	res := RunGeoASN(Options{IPs: []string{"1.1.1.1"}, Logf: quietLogf})
	rows := res.Data["ips"].([]geoIPRow)
	if rows[0].Source != "" || !strings.Contains(rows[0].Note, "失败") {
		t.Errorf("全源失败应记行内注记: %+v", rows[0])
	}
}
