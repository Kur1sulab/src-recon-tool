package whitelist

import "testing"

// 表驱动：正点名单硬校验。名单外一切 host（含其他私网/环回端口）必须全部拒绝。
func TestCheck(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		wantErr  bool
		wantHost string
	}{
		// ── 名单内：域名 / IP / 本机 mock（必须带端口 8799）──
		{"裸域名", "xycovo.com", false, "xycovo.com"},
		{"域名大小写归一", "XYCOVO.com", false, "xycovo.com"},
		{"域名带前后空格", "  xycovo.com  ", false, "xycovo.com"},
		{"https 全 URL", "https://xycovo.com/", false, "xycovo.com"},
		{"http 带路径", "http://xycovo.com/a/b?x=1", false, "xycovo.com"},
		{"裸 IP", "47.100.49.228", false, "47.100.49.228"},
		{"mock 带端口", "127.0.0.1:8799", false, "127.0.0.1:8799"},
		{"mock 全 URL 带路径", "http://127.0.0.1:8799/real", false, "127.0.0.1:8799"},
		{"mock https", "https://127.0.0.1:8799/jssite", false, "127.0.0.1:8799"},

		// ── 名单外：一律拒绝 ──
		{"其他环回端口", "127.0.0.1:80", true, ""},
		{"环回无端口", "127.0.0.1", true, ""},
		{"其他私网", "192.168.88.130", true, ""},
		{"其他私网带端口", "10.0.0.5:8080", true, ""},
		{"localhost", "localhost", true, ""},
		{"子域不在名单", "www.xycovo.com", true, ""},
		{"相似域名", "xycovo.com.evil.io", true, ""},
		{"未知公网", "1.2.3.4", true, ""},
		{"未知域名", "example.com", true, ""},
		{"IPv6", "[::1]:8799", true, ""},

		// ── 格式非法 ──
		{"空串", "", true, ""},
		{"纯空格", "   ", true, ""},
		{"目录穿越", "http://127.0.0.1:8799/../etc", true, ""},
		{"带用户信息", "http://user:pass@xycovo.com/", true, ""},
		{"非法端口", "127.0.0.1:99999", true, ""},
		{"端口为零", "127.0.0.1:0", true, ""},
		{"ftp 协议", "ftp://xycovo.com/", true, ""},
		{"含空格", "xycovo.com/xx yy", true, ""},
		{"控制字符", "xycovo.com\nevil", true, ""},
		{"非 ASCII", "xycovo.com／x", true, ""},
		{"裸域名带路径", "xycovo.com/admin", true, ""},
		{"百分号编码点穿越", "http://127.0.0.1:8799/.%2e/.%2e/", true, ""},
		{"百分号编码点大写", "http://127.0.0.1:8799/%2E%2E/", true, ""},
		{"百分号编码斜杠", "http://127.0.0.1:8799/real%2f..", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, err := Check(c.target)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Check(%q) 应拒绝，却得到 host=%q", c.target, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check(%q) 应通过，却得到错误: %v", c.target, err)
			}
			if host != c.wantHost {
				t.Fatalf("Check(%q) host = %q, 期望 %q", c.target, host, c.wantHost)
			}
		})
	}
}

func TestEntries(t *testing.T) {
	if len(Entries) != 3 {
		t.Fatalf("名单应为 3 项（xycovo.com / 47.100.49.228 / 127.0.0.1:8799），实际 %d", len(Entries))
	}
}
