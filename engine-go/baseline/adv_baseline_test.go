package baseline

// adv_baseline_test.go — 对抗轮（2026-10-06 基线检查红队）。零外网：全部靶标为
// 127.0.0.1 httptest / 包内注入桩；外部数据源（RDAP/CDX/geo/DoH）全部打桩。
// 攻击面：恶意 DNS TXT / 恶意 sitemap XML（DOCTYPE/ENTITY 变体 + 外带监听器）/
// 恶意 JSON（错型/深嵌套/巨串） / 超长响应头 / 畸形 Cookie / 重定向环 /
// 私网落点 302 / robots.txt Sitemap 任意首跳。
// 验收口径：fail-closed——拒绝或失败包络，不编造、不崩溃、不死循环、不越界。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/jsonx"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// ── 共用：严格逐跳策略（模拟「公网入口」语义：拒绝一切私网/环回落点）──

// strictHop 计数版严格策略：对每个落点跑真实 CheckHTTPURL(allowPrivate=false)，
// 127.0.0.1/169.254/[::1] 全拒。calls 记录策略被咨询次数。
func strictHop(calls *int64) func(entryURL string) func(string) error {
	return func(entryURL string) func(string) error {
		return func(next string) error {
			atomic.AddInt64(calls, 1)
			_, err := netutil.CheckHTTPURL(next, false)
			return err
		}
	}
}

// allowHop 授权内网语义（模拟私网入口/AllowPrivate=true 的真实策略）：
// 私网落点放行，仅做协议白名单校验。
func allowHop(calls *int64) func(entryURL string) func(string) error {
	return func(entryURL string) func(string) error {
		return func(next string) error {
			atomic.AddInt64(calls, 1)
			_, err := netutil.CheckHTTPURL(next, true)
			return err
		}
	}
}

func setHopPolicy(t *testing.T, f func(entryURL string) func(string) error) {
	t.Helper()
	old := hopPolicyFor
	hopPolicyFor = f
	t.Cleanup(func() { hopPolicyFor = old })
}

// hitCounter httptest 包装：记录命中次数 + 可变 handler。
type hitServer struct {
	*httptest.Server
	hits    int64
	handler func(w http.ResponseWriter, r *http.Request)
}

func newHitServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *hitServer {
	t.Helper()
	s := &hitServer{handler: h}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.hits, 1)
		s.handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// ── 1. 恶意 sitemap XML（DOCTYPE/ENTITY 变体 + 外带监听器）──

func TestAdvSitemapXXEVariants(t *testing.T) {
	exfil := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pwned")
	})
	var body string
	srv := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			http.NotFound(w, r)
		case "/sitemap.xml":
			fmt.Fprint(w, body)
		default:
			fmt.Fprint(w, "<html><title>adv</title></html>")
		}
	})
	o := Options{Domain: "adv.example.test", URL: srv.URL, Out: t.TempDir(), AllowPrivate: true}

	variants := map[string]string{
		"外部实体http外带":     fmt.Sprintf(`<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY xxe SYSTEM "%s/exfil">]><urlset><url><loc>&xxe;</loc></url></urlset>`, exfil.URL),
		"外部实体file":       `<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><urlset><url><loc>&xxe;</loc></url></urlset>`,
		"billion-laughs": `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><urlset><url><loc>&lol3;</loc></url></urlset>`,
		"小写doctype":      `<?xml version="1.0"?><!doctype r [<!ENTITY x "y">]><urlset><url><loc>http://a/1</loc></url></urlset>`,
		"无DOCTYPE悬空实体":   `<urlset><url><loc>&xxe;</loc></url></urlset>`,
	}
	for name, payload := range variants {
		body = payload
		res := RunWebfiles(o)
		if res.Error != "" {
			t.Errorf("[%s] 模块不应整体失败（应按源拒绝）: %s", name, res.Error)
		}
		notes, _ := res.Data["sitemap"].(map[string]any)
		if notes == nil {
			t.Fatalf("[%s] 缺 sitemap 数据", name)
		}
		urls, _ := notes["urls"].([]string)
		for _, u := range urls {
			if strings.Contains(u, "pwned") || strings.Contains(u, "root:") || strings.Contains(u, "lololol") {
				t.Errorf("[%s] 实体内容被展开进 loc: %q", name, u)
			}
		}
		rejected := false
		for _, n := range notes["notes"].([]string) {
			if strings.Contains(n, "DOCTYPE") || strings.Contains(n, "ENTITY") || strings.Contains(n, "解析失败") {
				rejected = true
			}
		}
		if !rejected {
			t.Errorf("[%s] 应记录拒绝/解析失败注记: %v", name, notes["notes"])
		}
	}
	// 外带监听器零命中：DOCTYPE/ENTITY 必须在解析前拦下，任何实体解析都不发生
	if n := atomic.LoadInt64(&exfil.hits); n != 0 {
		t.Errorf("外带监听器被命中 %d 次（XXE 拦截失效）", n)
	}
	// 正向对照：干净 sitemap 正常收录
	body = `<?xml version="1.0"?><urlset><url><loc>http://a.test/1</loc></url></urlset>`
	res := RunWebfiles(o)
	urls := res.Data["sitemap"].(map[string]any)["urls"].([]string)
	if len(urls) != 1 || urls[0] != "http://a.test/1" {
		t.Errorf("干净 sitemap 对照失败: %v", urls)
	}
	// UTF-16 变体：BOM + UTF-16LE 编码的 DOCTYPE（编码混淆绕过尝试）
	body = "\xff\xfe" + utf16le(`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><urlset/>`)
	res = RunWebfiles(o)
	if res.Error != "" {
		t.Errorf("UTF-16 变体不应整体失败: %s", res.Error)
	}
	if n := atomic.LoadInt64(&exfil.hits); n != 0 {
		t.Errorf("UTF-16 变体外带命中 %d 次", n)
	}
}

func utf16le(s string) string {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), 0)
	}
	return string(b)
}

// ── 2. robots.txt Sitemap 任意首跳（F1 已修·终修轮：首跳与重定向腿同权过闸）──

func TestAdvRobotsSitemapFirstHopGated(t *testing.T) {
	const secret = "cluster-node-token-ADV-7713"
	calls := int64(0)
	setHopPolicy(t, strictHop(&calls)) // 公网入口语义：拒一切私网/环回落点

	// inner 模拟「仅内网可达的服务」：以合法 sitemap XML 形态回显机密
	inner := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>http://inner.test/leak?token=%s</loc></url></urlset>`, secret)
	})
	outer := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nDisallow: /admin\nSitemap: %s/secret-service-status\n", inner.URL)
	})
	res := RunWebfiles(Options{Domain: "adv.example.test", URL: outer.URL, Out: t.TempDir(), AllowPrivate: true})

	if n := atomic.LoadInt64(&inner.hits); n != 0 {
		t.Fatalf("内网靶被命中 %d 次——robots Sitemap 首跳未过边界闸（F1 回归）", n)
	}
	if atomic.LoadInt64(&calls) == 0 {
		t.Error("Sitemap 首跳未咨询边界策略（F1：首跳应与重定向腿同权）")
	}
	gated := false
	notes, _ := res.Data["sitemap"].(map[string]any)["notes"].([]string)
	for _, n := range notes {
		if strings.Contains(n, "边界校验拒绝") {
			gated = true
		}
	}
	if !gated {
		t.Errorf("被拒首跳应记入 sitemap notes: %v", notes)
	}
	// 被拒源的响应内容不得回流进包络（零请求 → 零回读）
	if pj := jsonx.Pretty(res); strings.Contains(pj, secret) {
		t.Error("机密出现在 webfiles JSON 包络（被拒源不应产生响应）")
	}
}

// 对照组：授权内网语义（allowPrivate 放行策略）下，robots Sitemap 首跳照常
// 抓取收录——边界闸拒的是「公网入口策略下的越界落点」，不是一刀切拒外联。
func TestAdvRobotsSitemapFirstHopAllowedOnPrivateEntry(t *testing.T) {
	const secret = "cluster-node-token-ADV-7713"
	calls := int64(0)
	setHopPolicy(t, allowHop(&calls))

	inner := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>http://inner.test/leak?token=%s</loc></url></urlset>`, secret)
	})
	outer := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nSitemap: %s/secret-service-status\n", inner.URL)
	})
	res := RunWebfiles(Options{Domain: "adv.example.test", URL: outer.URL, Out: t.TempDir(), AllowPrivate: true})

	if n := atomic.LoadInt64(&inner.hits); n == 0 {
		t.Fatal("授权内网语义下 Sitemap 首跳应照常抓取")
	}
	urls, _ := res.Data["sitemap"].(map[string]any)["urls"].([]string)
	hitsSecret := false
	for _, u := range urls {
		if strings.Contains(u, secret) {
			hitsSecret = true
		}
	}
	if !hitsSecret {
		t.Errorf("授权内网首跳响应应收录进 loc: %v", urls)
	}
}

// 对照组：同一 Sitemap URL 若走 302 再到机密——重定向路径受真实 HopPolicy
// 约束（入口私网 → allowPrivate=true → 环回落点放行）。此对照钉死：webfiles
// 里「有策略」的只有重定向腿；首跳腿（F1）连策略咨询都没有。
func TestAdvRobotsSitemapRedirectFollowedOnPrivateEntry(t *testing.T) {
	const secret = "cluster-node-token-ADV-7713"
	inner := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			w.Header().Set("Location", "/secret")
			w.WriteHeader(302)
			return
		}
		fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>http://inner.test/leak?token=%s</loc></url></urlset>`, secret)
	})
	outer := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Sitemap: %s/go\n", inner.URL)
	})
	res := RunWebfiles(Options{Domain: "adv.example.test", URL: outer.URL, Out: t.TempDir(), AllowPrivate: true})
	urls, _ := res.Data["sitemap"].(map[string]any)["urls"].([]string)
	hitsSecret := false
	for _, u := range urls {
		if strings.Contains(u, secret) {
			hitsSecret = true
		}
	}
	// 入口=127.0.0.1（授权内网靶标）时真实 HopPolicy 放行私网落点 → 302 腿跟随，
	// 机密经 /secret 302 落腿取回。若此断言变红说明 302 腿也开始拒绝私网（策略收紧）。
	if !hitsSecret {
		t.Errorf("私网入口下 302 腿应跟随（HopPolicy allowPrivate）: %v", urls)
	}
}

// ── 3. 重定向环（secheaders 手动逐跳 / webfiles Fetch 跟随）──

func TestAdvSecHeadersRedirectLoop(t *testing.T) {
	for name, mode := range map[string]string{"自环": "self", "互环": "ab"} {
		var a, b *hitServer
		a = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case mode == "self":
				w.Header().Set("Location", a.URL+"/loop")
				w.WriteHeader(302)
			case r.URL.Path == "/a":
				w.Header().Set("Location", b.URL+"/b")
				w.WriteHeader(302)
			default:
				w.Header().Set("Location", a.URL+"/a")
				w.WriteHeader(302)
			}
		})
		b = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", a.URL+"/a")
			w.WriteHeader(302)
		})
		done := make(chan Result, 1)
		go func() { done <- RunSecHeaders(Options{Domain: "adv.example.test", URL: a.URL, AllowPrivate: true}) }()
		select {
		case res := <-done:
			if res.Error == "" {
				t.Errorf("[%s] 重定向环应产生失败包络（终响应未取得）", name)
			}
			hops, _ := res.Data["hops"].([]secHop)
			if len(hops) > secMaxHops {
				t.Errorf("[%s] 逐跳数 %d 超过上限 %d", name, len(hops), secMaxHops)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("[%s] 重定向环死循环（20s 未返回）", name)
		}
	}
}

func TestAdvWebfilesRedirectLoop(t *testing.T) {
	var a *hitServer
	a = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", a.URL+"/x")
		w.WriteHeader(302)
	})
	done := make(chan Result, 1)
	go func() {
		done <- RunWebfiles(Options{Domain: "adv.example.test", URL: a.URL, Out: t.TempDir(), AllowPrivate: true})
	}()
	select {
	case res := <-done:
		if res.Error != "" {
			t.Errorf("webfiles 对环不应整体失败（按源失败）: %s", res.Error)
		}
		sm := res.Data["sitemap"].(map[string]any)
		urls, _ := sm["urls"].([]string)
		if len(urls) != 0 {
			t.Errorf("环不应产生 loc: %v", urls)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("webfiles 重定向环死循环（20s 未返回）")
	}
}

// ── 4. 私网落点 302（严格策略下必须拦，且不外发请求）──

func TestAdvSecHeadersPrivateLandingBlocked(t *testing.T) {
	calls := int64(0)
	setHopPolicy(t, strictHop(&calls))
	inner := newHitServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "internal") })
	for name, loc := range map[string]string{
		"云元数据": "http://169.254.169.254/latest/meta-data/",
		"环回v6": "http://[::1]/x",
		"环回v4": inner.URL + "/secret",
		"伪造域名": "http://metadata.google.internal/computeMetadata/v1/",
	} {
		srv := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", loc)
			w.WriteHeader(302)
		})
		res := RunSecHeaders(Options{Domain: "adv.example.test", URL: srv.URL, AllowPrivate: true})
		if res.Error == "" {
			t.Errorf("[%s] 私网落点拒绝后应有失败包络", name)
		}
		blocked := false
		hops, _ := res.Data["hops"].([]secHop)
		for _, h := range hops {
			if h.Blocked {
				blocked = true
			}
		}
		if !blocked {
			t.Errorf("[%s] hops 中无 Blocked 标记: %+v", name, hops)
		}
		// F2 已修（终修轮）：blocked-hop 风险收集提前到 finalHeader==nil 早退
		// 之前，「重定向落点被边界校验拒绝」真正进 risks（不再只是 hops[].blocked）。
		riskBlocked := false
		for _, rk := range res.Risks {
			if strings.Contains(rk.Title, "落点被边界校验拒绝") {
				riskBlocked = true
			}
		}
		if !riskBlocked {
			t.Errorf("[%s] risks 缺「重定向落点被边界校验拒绝」（F2 回归：早退前未 flush）", name)
		}
	}
	if n := atomic.LoadInt64(&inner.hits); n != 0 {
		t.Errorf("内网靶被命中 %d 次（私网落点未拦住）", n)
	}
	if atomic.LoadInt64(&calls) == 0 {
		t.Error("严格策略从未被咨询")
	}
}

// ── 5. 超长响应头 ──

func TestAdvSecHeadersOverlongHeaders(t *testing.T) {
	big := strings.Repeat("x", 8<<20) // 8MB
	srv := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", big)
		w.Header().Add("Set-Cookie", "big="+strings.Repeat("c", 2<<20)+"; Path=/")
		w.Header().Set("Server", "cloudflare")
		fmt.Fprint(w, "ok")
	})
	res := RunSecHeaders(Options{Domain: "adv.example.test", URL: srv.URL, AllowPrivate: true})
	if res.Error != "" {
		// 分支 A：传输层拒绝超长头 → 失败包络 = fail-closed（记录在案）
		t.Logf("传输层拒绝 8MB 响应头（fail-closed）: %s", res.Error)
		return
	}
	// 分支 B：客户端照单全收 → 产物体积放大（记录放大倍率）
	rows, _ := res.Data["headers"].([]secHeaderRow)
	xctoOK := false
	for _, r := range rows {
		if r.Name == "X-Content-Type-Options" && r.State == "ok" {
			xctoOK = true
		}
	}
	if !xctoOK {
		t.Errorf("超长 nosniff 应判 ok（取值存在即达标），rows=%+v 摘要", len(rows))
	}
	body := jsonx.Pretty(res)
	t.Logf("8MB 头被接受：webfiles 产物 JSON 体积 %d 字节（无头长上限，放大风险）", len(body))
	if len(body) < 8<<20 {
		t.Errorf("产物应包含完整超长值（体积 %d）", len(body))
	}
}

// 边界探测：传输层对响应头总量的拒收阈值（8MB 已证被拒，这里找翻转点）。
func TestAdvSecHeadersHeaderSizeBoundary(t *testing.T) {
	for _, size := range []int{64 << 10, 256 << 10, 1 << 20} {
		size := size
		srv := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", strings.Repeat("x", size))
			fmt.Fprint(w, "ok")
		})
		res := RunSecHeaders(Options{Domain: "adv.example.test", URL: srv.URL, AllowPrivate: true})
		if res.Error != "" {
			t.Logf("头值 %d 字节：传输层拒绝（fail-closed）", size)
			continue
		}
		body := jsonx.Pretty(res)
		noteLen := 0
		for _, r := range res.Data["headers"].([]secHeaderRow) {
			if r.Name == "X-Content-Type-Options" {
				noteLen = len(r.Note)
			}
		}
		t.Logf("头值 %d 字节：被接受；产物 %d 字节；XCTO note 长 %d（取值全量复制进 note）", size, len(body), noteLen)
	}
}

// ── 6. 畸形 Cookie ──

func TestAdvSecHeadersMalformedCookies(t *testing.T) {
	srv := newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "broken")                      // 无 =
		h.Add("Set-Cookie", "a=b; SameSite=Bogus; Secure") // 非法 SameSite
		h.Add("Set-Cookie", "c=d; Domain=evil.test; Path=/x; Secure; HttpOnly; SameSite=lax")
		h.Add("Set-Cookie", "e="+strings.Repeat("v", 1<<20)) // 1MB 值，无任何安全属性
		h.Add("Set-Cookie", "f=g; SameSite=")                // 空 SameSite
		fmt.Fprint(w, "ok")
	})
	done := make(chan Result, 1)
	go func() { done <- RunSecHeaders(Options{Domain: "adv.example.test", URL: srv.URL, AllowPrivate: true}) }()
	select {
	case res := <-done:
		if res.Error != "" {
			t.Fatalf("畸形 Cookie 不应整体失败: %s", res.Error)
		}
		rows, _ := res.Data["cookies"].([]secCookieRow)
		// 审计行只含属性不含值（1MB 值不进产物 = 天然收口）；broken（无 =）被
		// Go readSetCookies 丢弃；每个缺属性的 Cookie 必须如实标注。
		totalIssues := 0
		sawBigNoAttrs := false
		for _, c := range rows {
			totalIssues += len(c.Issues)
			if c.Name == "e" && len(c.Issues) >= 3 {
				sawBigNoAttrs = true // 1MB 值 Cookie：缺 Secure/HttpOnly/SameSite 全标
			}
			if c.Name == "c" && len(c.Issues) != 0 {
				t.Errorf("属性齐备的 Cookie %q 不应有缺项: %+v", c.Name, c)
			}
		}
		if !sawBigNoAttrs {
			t.Errorf("1MB 无属性 Cookie 未被如实审计: %+v", rows)
		}
		if totalIssues == 0 {
			t.Errorf("畸形 Cookie 池 %d 行居然零缺项标记: %+v", len(rows), rows)
		}
		t.Logf("畸形 Cookie 池解析出 %d 行；缺项标记共 %d 处", len(rows), totalIssues)
	case <-time.After(20 * time.Second):
		t.Fatal("畸形 Cookie 处理卡死")
	}
}

// ── 7. 恶意 DNS TXT（mailsec：SPF 自环/互环、1MB 记录、非法 UTF-8、DMARC pct 溢出、DKIM 垃圾 p=）──

func TestAdvMailsecHostileTXT(t *testing.T) {
	old := dns
	t.Cleanup(func() { dns = old })
	dns = &fakeDNS{txt: map[string][]string{
		"adv.example.test": {
			"v=spf1 include:loop.test include:mutual.test -all",
			"v=spf1 -all\x00\xff junk", // 非法字节混入
			strings.Repeat("x", 1<<20), // 1MB 噪声 TXT
		},
		"loop.test":   {"v=spf1 include:loop.test -all"},
		"mutual.test": {"v=spf1 include:flip.test -all"},
		"flip.test":   {"v=spf1 include:mutual.test -all"},
		"_dmarc.adv.example.test": {
			"v=dmarc1; p=reject; pct=" + strings.Repeat("9", 30), // pct 溢出
		},
		"dkim._domainkey.adv.example.test": {
			"v=DKIM1; k=rsa; p=" + strings.Repeat("Z", 4<<20), // 4MB 非法 base64 公钥
			"v=DKIM1; p=not-base64!!!",
		},
	}}
	done := make(chan Result, 1)
	go func() { done <- RunMailsec(Options{Domain: "adv.example.test"}) }()
	select {
	case res := <-done:
		if res.Error != "" {
			t.Fatalf("恶意 TXT 不应整体失败: %s", res.Error)
		}
		spf, _ := res.Data["spf"].(map[string]any)
		expanded, _ := spf["expanded"].([]string)
		if len(expanded) > 21 {
			t.Errorf("SPF 展开条目 %d 超出封顶（环未拦住）", len(expanded))
		}
		if _, err := json.Marshal(res); err != nil {
			t.Fatalf("结果不可 JSON 序列化: %v", err)
		}
		// 非 SPF/DMARC/DKIM 形态的 1MB 噪声 TXT 应被 mailsec 丢弃（fail-closed）
		if body := jsonx.Pretty(res); strings.Contains(body, strings.Repeat("x", 4096)) {
			t.Error("无关噪声 TXT 被收进 mailsec 产物")
		}
		t.Logf("SPF 展开 %d 条（封顶内）", len(expanded))
	case <-time.After(30 * time.Second):
		t.Fatal("SPF include 环死循环（30s 未返回）")
	}
}

// ── 8. dnsrec：恶意 TXT + 错误分类截断 + DoH 敌意 JSON ──

func TestAdvDNSRecHostileTXT(t *testing.T) {
	old := dns
	t.Cleanup(func() { dns = old })
	dns = &fakeDNS{txt: map[string][]string{
		"adv.example.test": {
			strings.Repeat("\x00\x01\x02", 1<<18), // 786KB 控制字节
			strings.Repeat("日", 1<<18),            // 多字节
		},
	}}
	res := RunDNSRec(Options{Domain: "adv.example.test"})
	if res.Error != "" {
		t.Fatalf("dnsrec 不应失败: %s", res.Error)
	}
	if _, err := json.Marshal(res); err != nil {
		t.Fatalf("控制字节/多字节 TXT 破坏序列化: %v", err)
	}
}

func TestAdvDNSErrClassifyTruncation(t *testing.T) {
	// 119 ASCII + 1 个 3 字节汉字起点：按字节截断可能劈开 UTF-8 序列——
	// 验证产物序列化安全（encoding/json 以 U+FFFD 兜底），不 panic。
	long := strings.Repeat("e", 119) + "日日日"
	got := dnsErrClassify(errors.New(long))
	if got == "" {
		t.Fatal("分类结果为空")
	}
	if _, err := json.Marshal(map[string]string{"e": got}); err != nil {
		t.Fatalf("截断后的错误串不可序列化: %v", err)
	}
}

func TestAdvDoHHostileJSON(t *testing.T) {
	oldDoh := dohFetch
	t.Cleanup(func() { dohFetch = oldDoh })
	dohFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		// Status 以字符串伪造（SERVIFAIL）——生产解析断言 float64 会放行
		return map[string]any{
			"Status": "SERVFAIL",
			"Answer": []any{1, "x", map[string]any{"data": 42}, map[string]any{"data": "ok-str"}},
		}, nil
	}
	out, err := dohQuery("adv.example.test", dohTypeSOA)
	// F5 已修（终修轮）：Status 在场但非数值按查询失败处理——堵敌意 DoH 源
	// 以字符串 Status 逃过 DNSSEC 判定、投喂伪造 DS/DNSKEY。
	if err == nil {
		t.Fatalf("非数值 Status 应按查询失败处理（F5 回归），got %v", out)
	}
	for _, s := range out {
		if s != "ok-str" {
			t.Errorf("非字符串 data 被收进结果: %q", s)
		}
	}
	// 巨串 Answer
	dohFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		return map[string]any{"Answer": []any{map[string]any{"data": strings.Repeat("A", 2<<20)}}}, nil
	}
	out, err = dohQuery("adv.example.test", dohTypeCAA)
	if err != nil || len(out) != 1 {
		t.Fatalf("巨串应如实收录: %v %v", out, err)
	}
}

// ── 9. whois：敌意 RDAP JSON + 43 端口 referral 环 ──

func TestAdvWhoisHostileRDAP(t *testing.T) {
	oldR := rdapFetch
	oldQ := whoisQuery
	t.Cleanup(func() { rdapFetch = oldR; whoisQuery = oldQ })

	cases := map[string]func() (map[string]any, error){
		"顶层不是对象": func() (map[string]any, error) {
			return nil, errors.New("RDAP 响应非 JSON: json: cannot unmarshal array into Go value of type map[string]interface {}")
		},
		"全错型": func() (map[string]any, error) {
			m := map[string]any{}
			if err := json.Unmarshal([]byte(`{"events":[{"eventAction":123,"eventDate":{"x":1}}],
				"entities":[{"roles":"registrar","vcardArray":["vcard",[["fn","text","",[""]]]]}],
				"nameservers":[{"ldhName":42}],"status":["x",5]}`), &m); err != nil {
				return nil, err
			}
			return m, nil
		},
		"深嵌套": func() (map[string]any, error) {
			n := 30000
			raw := strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n)
			var m map[string]any
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				return nil, fmt.Errorf("RDAP 响应非 JSON: %w", err)
			}
			return m, nil
		},
		"过期日期非RFC3339": func() (map[string]any, error) {
			var m map[string]any
			if err := json.Unmarshal([]byte(`{"events":[{"eventAction":"expiration","eventDate":"yesterday-ish"}],"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn","text","","Evil Registrar"]]]}]}`), &m); err != nil {
				return nil, err
			}
			return m, nil
		},
	}
	for name, stub := range cases {
		rdapFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) { return stub() }
		whoisQuery = func(server, query string, timeout time.Duration) (string, error) {
			return "no matching record", nil
		}
		done := make(chan Result, 1)
		go func() { done <- RunWhois(Options{Domain: "adv.example.test"}) }()
		select {
		case res := <-done:
			if res.Error != "" {
				t.Errorf("[%s] 敌意 RDAP 不应产生 Error（应回退或安全收纳）: %s", name, res.Error)
			}
			if _, err := json.Marshal(res); err != nil {
				t.Errorf("[%s] 序列化失败: %v", name, err)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("[%s] 卡死", name)
		}
	}
	// 正向：日期合法但格式伪造成超巨串
	rdapFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		var m map[string]any
		raw := `{"events":[{"eventAction":"expiration","eventDate":"` + strings.Repeat("9", 1<<20) + `"}]}`
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	res := RunWhois(Options{Domain: "adv.example.test"})
	if res.Error != "" {
		t.Errorf("巨串日期不应整体失败: %s", res.Error)
	}
}

func TestAdvWhoisReferralLoop(t *testing.T) {
	oldQ := whoisQuery
	t.Cleanup(func() { whoisQuery = oldQ })
	whoisQuery = func(server, query string, timeout time.Duration) (string, error) {
		switch {
		case strings.Contains(server, "iana"):
			return "refer: whois://a.test\n", nil
		case strings.Contains(server, "a.test"):
			return "Domain Name: X\nReferralServer: whois://b.test\n", nil
		case strings.Contains(server, "b.test"):
			return "Domain Name: X\nReferralServer: whois://a.test\n", nil
		}
		return "no match", nil
	}
	done := make(chan Result, 1)
	go func() { done <- RunWhois(Options{Domain: "adv.example.test"}) }()
	select {
	case res := <-done:
		if res.Error != "" {
			t.Fatalf("referral 环不应整体失败: %s", res.Error)
		}
		w, _ := res.Data["whois"].(whoisText)
		if w.Structured {
			t.Errorf("环文本不应被结构化: %+v", w)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("43 端口 referral 环死循环")
	}
}

// ── 10. geoasn：敌意 JSON（truthy 陷阱/错型/巨串）──

func TestAdvGeoASNHostileJSON(t *testing.T) {
	oldG := geoFetch
	oldS := geoSleep
	t.Cleanup(func() { geoFetch = oldG; geoSleep = oldS })
	geoSleep = func(time.Duration) {}

	// 三源全部「HTTP 200 但业务层失败」的伪造形态
	bodies := map[string]string{
		"ipwho.is":   `{"ip":"1.2.3.4","success":false,"message":"quota"}`,
		"ip-api.com": `{"status":"fail","message":"quota","query":"1.2.3.4"}`,
		"geojs":      `{"error":"quota"}`,
	}
	var calls int64
	geoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		atomic.AddInt64(&calls, 1)
		for k, b := range bodies {
			if strings.Contains(rawURL, strings.Split(k, ".")[0]) {
				var m map[string]any
				if err := json.Unmarshal([]byte(b), &m); err != nil {
					return nil, err
				}
				return m, nil
			}
		}
		return nil, fmt.Errorf("no stub for %s", rawURL)
	}
	res := RunGeoASN(Options{Domain: "adv.example.test", IPs: []string{"93.184.216.34"}})
	rows, _ := res.Data["ips"].([]geoIPRow)
	if len(rows) != 1 || rows[0].Source != "" {
		t.Errorf("假 200 应全部判失败且不编造: %+v", rows)
	}
	// truthy 陷阱：success 以字符串 "false"（非 bool）→ 不得被当成功
	geoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{"success":"false","country":"CN"}`), &m)
		return m, nil
	}
	res = RunGeoASN(Options{Domain: "adv.example.test", IPs: []string{"1.2.3.4"}})
	rows, _ = res.Data["ips"].([]geoIPRow)
	if len(rows) != 1 && rows[0].Source != "" {
		// 若 truthy 被当成功，Country=CN 会入库——记录实际行为
		t.Logf("truthy \"false\" 行为: %+v", rows[0])
	}
	// 巨串 country：如实收纳 + 产物放大（记录）
	geoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{"country":"`+strings.Repeat("A", 2<<20)+`","success":true}`), &m)
		return m, nil
	}
	res = RunGeoASN(Options{Domain: "adv.example.test", IPs: []string{"1.2.3.4"}})
	body := jsonx.Pretty(res)
	if len(body) < 2<<20 {
		t.Errorf("巨串应如实进产物: %d", len(body))
	}
	t.Logf("geo 巨串产物 %d 字节（无字段长上限）", len(body))
}

// ── 11. archives：敌意 CDX（页数注入/超大行数/敌意 URL 行）──

func TestAdvArchivesHostileCDX(t *testing.T) {
	oldC := cdxFetch
	oldSl := retrySleepCDX
	t.Cleanup(func() { cdxFetch = oldC; retrySleepCDX = oldSl })
	retrySleepCDX = func(time.Duration) {}

	for name, npBody := range map[string]string{
		"负数": "-5", "巨数": "999999999999999999999999", "0x十六进制": "0x10", "加号": "+7", "垃圾": "<html>503</html>", "空": "",
	} {
		var pageReqs int64
		cdxFetch = func(rawURL string, timeout time.Duration) (string, error) {
			atomic.AddInt64(&pageReqs, 1)
			if strings.Contains(rawURL, "showNumPages=true") {
				return npBody, nil
			}
			return "http://a.test/1 20260101 text/html 200\n", nil
		}
		rows, truncated, err := fetchCDX("adv.example.test", cdxMaxLines)
		if err != nil {
			t.Fatalf("[%s] 不应出错: %v", name, err)
		}
		if truncated {
			t.Errorf("[%s] 单页少量行不应截断", name)
		}
		if int(pageReqs) > cdxMaxPages+1 {
			t.Errorf("[%s] 页数请求 %d 次未封顶", name, pageReqs)
		}
		if len(rows) != 1 {
			t.Errorf("[%s] 行数应恒为 1，得 %d", name, len(rows))
		}
	}
	// 超行数：60k 行 → 截断在 5 万
	cdxFetch = func(rawURL string, timeout time.Duration) (string, error) {
		if strings.Contains(rawURL, "showNumPages=true") {
			return "2", nil
		}
		var b strings.Builder
		for i := 0; i < 60000; i++ {
			fmt.Fprintf(&b, "http://a.test/p%d 20260101 text/html 200\n", i)
		}
		return b.String(), nil
	}
	rows, truncated, err := fetchCDX("adv.example.test", cdxMaxLines)
	if err != nil || !truncated || len(rows) != cdxMaxLines {
		t.Fatalf("超行数截断失真: n=%d truncated=%v err=%v", len(rows), truncated, err)
	}
	// 敌意 URL 行：控制字符/非法 scheme/超长
	cdxFetch = func(rawURL string, timeout time.Duration) (string, error) {
		if strings.Contains(rawURL, "showNumPages=true") {
			return "1", nil
		}
		return "javascript:alert(1) x 1\nhttp://a.test/\x01\x02admin x 1\nhttp://a.test/" + strings.Repeat("u", 4<<20) + " 1 x 1\n", nil
	}
	rows, truncated, err = fetchCDX("adv.example.test", cdxMaxLines)
	if err != nil || truncated {
		t.Fatalf("敌意行不应失败: %v %v", truncated, err)
	}
	// F4 已修（终修轮）：normalizeCDXURL 拒绝非 http(s) scheme（javascript:）
	// 与控制字符行（url.Parse 报错 → 跳过），只收合法 http(s) 行。
	for _, r := range rows {
		if strings.Contains(r.Original, "javascript:") {
			t.Errorf("非 http(s) CDX 行未过滤（F4 回归）: %q", r.Original)
		}
	}
	if len(rows) != 1 {
		t.Errorf("3 行敌意输入应收录 1 行合法 http(s) 行: %d (%+v)", len(rows), rows)
	}
}

// ── 14. webfiles sitemap 源有界性（审计 F2：源封顶 + 时间软预算）──

func TestAdvWebfilesSitemapBounded(t *testing.T) {
	// 源数量封顶：robots 塞 15 条 Sitemap 行，抓取次数不得超过 robotsMaxSitemaps
	var s *hitServer
	var fetches int64
	s = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/robots.txt":
			var b strings.Builder
			b.WriteString("User-agent: *\n")
			for i := 0; i < 15; i++ {
				fmt.Fprintf(&b, "Sitemap: %s/sm%d\n", s.URL, i)
			}
			fmt.Fprint(w, b.String())
		case strings.HasPrefix(r.URL.Path, "/sm"):
			atomic.AddInt64(&fetches, 1)
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>http://a.test/1</loc></url></urlset>`)
		default:
			fmt.Fprint(w, "<html><title>adv</title></html>")
		}
	})
	RunWebfiles(Options{Domain: "adv.example.test", URL: s.URL, Out: t.TempDir(), AllowPrivate: true})
	if n := atomic.LoadInt64(&fetches); n > robotsMaxSitemaps {
		t.Errorf("sitemap 源抓取 %d 次超封顶 %d（F2 回归：robots Sitemap 行数未封顶）", n, robotsMaxSitemaps)
	}

	// 时间软预算：预算调小 + 慢源（15ms/req），20 条 Sitemap 行不得全量抓完
	oldBudget := sitemapFetchBudget
	sitemapFetchBudget = 30 * time.Millisecond
	t.Cleanup(func() { sitemapFetchBudget = oldBudget })
	var slow *hitServer
	var slowFetches int64
	slow = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/robots.txt":
			var b strings.Builder
			b.WriteString("User-agent: *\n")
			for i := 0; i < 20; i++ {
				fmt.Fprintf(&b, "Sitemap: %s/sm%d\n", slow.URL, i)
			}
			fmt.Fprint(w, b.String())
		case strings.HasPrefix(r.URL.Path, "/sm"):
			atomic.AddInt64(&slowFetches, 1)
			time.Sleep(15 * time.Millisecond)
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>http://b.test/1</loc></url></urlset>`)
		default:
			fmt.Fprint(w, "<html><title>adv</title></html>")
		}
	})
	RunWebfiles(Options{Domain: "adv.example.test", URL: slow.URL, Out: t.TempDir(), AllowPrivate: true})
	if n := atomic.LoadInt64(&slowFetches); n >= 20 {
		t.Errorf("慢源 %d 次全量抓取，时间软预算未生效（F2 回归：60s 护栏弃管后仍无界外联）", n)
	}
}

// ── 15. whois referral 主机形状闸（审计 F3）──

func TestAdvWhoisReferralShapeGate(t *testing.T) {
	cases := map[string]bool{
		"whois.iana.org":         true,  // 合法形态
		"reg.test":               true,  // 合法形态
		"whois://reg.test/whois": false, // 剥前缀后带路径
		"javascript:alert(1)":    false, // 非 whois 形态（scheme 残留）
		"1.2.3.4:43":             false, // 带端口
		"-evil.test":             false, // 连字符开头
		"evil.test-":             false, // 连字符结尾
		".evil.test":             false, // 点开头
		"evil":                   false, // 无点（非域名形态）
		strings.Repeat("a", 300): false, // 超长
	}
	for in, want := range cases {
		if got := referralHostOK(extractReferral("ReferralServer: " + in)); got != want {
			t.Errorf("referral %q 形状闸判定 %v，应 %v", in, got, want)
		}
	}
}

// ── 12. 聚合器敌意端到端：检查级失败不破坏聚合，产物全部可解析 ──

func TestAdvAggregatorHostileEndToEnd(t *testing.T) {
	oldD := dns
	oldG, oldS := geoFetch, geoSleep
	oldR, oldQ := rdapFetch, whoisQuery
	oldC, oldSl := cdxFetch, retrySleepCDX
	t.Cleanup(func() {
		dns = oldD
		geoFetch, geoSleep = oldG, oldS
		rdapFetch, whoisQuery = oldR, oldQ
		cdxFetch, retrySleepCDX = oldC, oldSl
	})
	dns = &fakeDNS{txt: map[string][]string{"adv.example.test": {"v=spf1 include:loop.test -all", strings.Repeat("z", 1<<20)}, "loop.test": {"v=spf1 include:loop.test -all"}}}
	geoSleep = func(time.Duration) {}
	geoFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		return nil, errors.New("geo 请求失败: connectex: 模拟断网")
	}
	rdapFetch = func(rawURL string, timeout time.Duration) (map[string]any, error) {
		return nil, errors.New("RDAP 响应非 JSON: unexpected end of JSON input")
	}
	whoisQuery = func(server, query string, timeout time.Duration) (string, error) {
		return "", errors.New("dial tcp: 模拟断网")
	}
	retrySleepCDX = func(time.Duration) {}
	cdxFetch = func(rawURL string, timeout time.Duration) (string, error) {
		return "", errors.New("CDX 请求失败: 模拟断网")
	}
	// HTTP 侧：robots 404 / sitemap XXE / 首页重定向环（secheaders 走失败包络）
	var home *hitServer
	home = newHitServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			http.NotFound(w, r)
		case "/sitemap.xml":
			fmt.Fprint(w, `<!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><urlset/>`)
		default:
			w.Header().Set("Location", home.URL+"/loop")
			w.WriteHeader(302)
		}
	})
	out := t.TempDir()
	rec := &recorder{}
	err := Run(Options{
		Domain: "adv.example.test", URL: home.URL, Out: out,
		AllowPrivate: true, Emit: rec.emit, Logf: quietLogf,
	})
	if err != nil {
		t.Fatalf("检查级失败不得破坏聚合: %v", err)
	}
	for _, c := range checksOrder {
		p := filepath.Join(out, c+".json")
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Errorf("%s.json 未落盘: %v", c, rerr)
			continue
		}
		if !json.Valid(raw) {
			t.Errorf("%s.json 非 JSON", c)
			continue
		}
		var env map[string]any
		_ = json.Unmarshal(raw, &env)
		if strings.Contains(string(raw), `"risks": null`) {
			t.Errorf("%s.json risks 序列化为 null（应恒为数组）", c)
		}
		if c == "whois" && env["error"] == "" {
			t.Error("whois 双源全断应记 Error（不编造）")
		}
		if c == "geoasn" && env["error"] == "" {
			t.Error("geoasn 全源断应记 Error（不编造）")
		}
	}
	if n := strings.Count(strings.Join(rec.events, "\n"), "fail/"); n < 2 {
		t.Errorf("预期 ≥2 个 fail 事件（whois/geoasn），实际 %d: %v", n, rec.events)
	}
}
