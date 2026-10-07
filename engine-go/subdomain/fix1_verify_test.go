package subdomain

// fix1_verify_test.go — 第 1 轮审计+对抗修复的回归测试（engine-go/subdomain）：
//   1. P0 竞态：VerifySubs(doHTTP=true, workers≥2) 并发写 httpMap → fatal error
//      （审计 high#1 / 对抗 broke#1：verify.go:127 普通 map :142 无锁写）
//   2. 证据包结构 parity：死亡行 ips=[]/http={}（审计 medium#3）
//   3. 行序与探活结果映射在并发下保持正确

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestVerifySubsConcurrentHTTPProbeMap：doHTTP=true + 多 worker + 多可解析主机。
// 修复前该用例以高概率触发运行时 fatal error: concurrent map writes（本机 30 连跑
// 16 崩）；修复后（httpMap 改按索引切片）连跑稳定绿。运行时 fatal 无法被 recover，
// 崩了整个测试进程直接死——这就是红信号本身，无需断言。
func TestVerifySubsConcurrentHTTPProbeMap(t *testing.T) {
	subs := make([]string, 0, 32)
	for i := 0; i < 16; i++ {
		subs = append(subs, "127.0.0.1", "localhost")
	}
	for round := 0; round < 20; round++ {
		rows := VerifySubs(subs, 8, true, 120)
		if len(rows) != len(subs) {
			t.Fatalf("round %d: rows=%d want %d", round, len(rows), len(subs))
		}
		for i, r := range rows {
			if r.Host != subs[i] {
				t.Fatalf("round %d: 行序漂移 [%d]=%q", round, i, r.Host)
			}
			if !r.Alive || len(r.IPs) == 0 {
				t.Fatalf("round %d: %q 回环字面量应 alive", round, r.Host)
			}
		}
	}
}

// TestVerifyRowJSONMatchesPythonShape 钉死落盘 JSON 空值形态（与 Python
// verify_subs 的 dict 形态逐键对齐）：死亡行 ips=[]（非 null）、http={}（非六字段对象）；
// 探活成功行 http 为完整六键对象；键序 host,ips,alive,http。
func TestVerifyRowJSONMatchesPythonShape(t *testing.T) {
	dead := VerifyRow{Host: "..", IPs: nil, Alive: false, HTTP: ProbeResult{}}
	b, err := json.Marshal(dead)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	want := `{"host":"..","ips":[],"alive":false,"http":{}}`
	if got != want {
		t.Fatalf("死亡行 JSON 形态漂移:\n got  %s\n want %s", got, want)
	}
	// 空切片也必须出 []（DNS 失败返回 nil 与 [] 两种来源都要归一）
	dead2 := VerifyRow{Host: "h", IPs: []string{}, Alive: false}
	b2, _ := json.Marshal(dead2)
	if !strings.Contains(string(b2), `"ips":[]`) {
		t.Fatalf("空切片应序列化为 []: %s", b2)
	}

	live := VerifyRow{Host: "127.0.0.1", IPs: []string{"127.0.0.1"}, Alive: true,
		HTTP: ProbeResult{Scheme: "http", Status: 404, Server: "", Ctype: "text/html",
			Title: "", FinalURL: "http://127.0.0.1:1"}}
	b3, _ := json.Marshal(live)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b3, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"host", "ips", "alive", "http"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("存活行缺键 %s: %s", k, b3)
		}
	}
	var hm map[string]any
	if err := json.Unmarshal(m["http"], &hm); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scheme", "status", "server", "ctype", "title", "final_url"} {
		if _, ok := hm[k]; !ok {
			t.Fatalf("存活行 http 缺键 %s: %s", k, m["http"])
		}
	}
}

// TestVerifySubsRowsKeepInputOrderWithHTTP：doHTTP=true 下行序 + 探活结果按输入行对位。
func TestVerifySubsRowsKeepInputOrderWithHTTP(t *testing.T) {
	subs := []string{"127.0.0.1", "localhost", "127.0.0.1"}
	rows := VerifySubs(subs, 4, true, 120)
	if len(rows) != 3 {
		t.Fatalf("rows=%d", len(rows))
	}
	for i, r := range rows {
		if r.Host != subs[i] {
			t.Fatalf("行 [%d]=%q, want %q", i, r.Host, subs[i])
		}
	}
	// 同主机的探活结果必须一致（127.0.0.1 出现在第 0、2 行）——
	// 若索引映射错位（写串行/读错位）该性质即破。
	if rows[0].HTTP != rows[2].HTTP {
		t.Fatalf("同主机探活结果应对位一致: [%d]=%+v [%d]=%+v", 0, rows[0].HTTP, 2, rows[2].HTTP)
	}
}

// portOfUnused 防御性辅助：确证测试依赖的 127.0.0.1/localhost 在本机可解析。
func TestLoopbackResolvableAnchors(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost"} {
		if len(DNSLookup(h, 3e9)) == 0 {
			t.Fatalf("锚点 %s 在本机应可解析（竞态用例依赖）", h)
		}
	}
}
