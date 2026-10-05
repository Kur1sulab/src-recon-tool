package whitelist

import "testing"

// 表驱动：目标卫生校验与归一化。目标本身全部默认授权（用户裁定
// 2026-10-05）——任何格式合法的域名/IP/URL 都放行；只有格式问题拒绝。
func TestCheck(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		wantErr  bool
		wantHost string
	}{
		// ── 格式合法：全部放行（不再有名单成员判定）──
		{"裸域名", "xycovo.com", false, "xycovo.com"},
		{"域名大小写归一", "XYCOVO.com", false, "xycovo.com"},
		{"域名带前后空格", "  xycovo.com  ", false, "xycovo.com"},
		{"域名双尾点归一", "example.com..", false, "example.com"},
		{"https 全 URL", "https://xycovo.com/", false, "xycovo.com"},
		{"http 带路径", "http://xycovo.com/a/b?x=1", false, "xycovo.com"},
		{"裸 IP", "47.100.49.228", false, "47.100.49.228"},
		{"本机带端口", "127.0.0.1:8799", false, "127.0.0.1:8799"},
		{"本机 URL 带路径", "http://127.0.0.1:8799/real", false, "127.0.0.1:8799"},
		{"任意公网域名", "example.com", false, "example.com"},
		{"任意子域", "www.xycovo.com", false, "www.xycovo.com"},
		{"任意公网 IP", "1.2.3.4", false, "1.2.3.4"},
		{"localhost", "localhost", false, "localhost"},
		{"其他私网", "192.168.88.130", false, "192.168.88.130"},
		{"私网带端口", "10.0.0.5:8080", false, "10.0.0.5:8080"},
		{"环回无端口", "127.0.0.1", false, "127.0.0.1"},
		{"其他环回端口", "127.0.0.1:80", false, "127.0.0.1:80"},
		{"十进制分段 IP 形态", "0177.0.0.1", false, "0177.0.0.1"},

		// ── 格式非法：一律拒绝 ──
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
		{"裸 IPv6 字面量", "::1", true, ""},
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
