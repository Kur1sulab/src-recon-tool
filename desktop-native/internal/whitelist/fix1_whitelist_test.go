package whitelist

// fix1_whitelist_test.go — 对抗轮模糊表固化（fixesNeeded P3），口径随
// 2026-10-05 用户裁定更新：目标全部默认授权，本表只钉「格式卫生」——
// 控制字符与 CRLF / 超长 / userinfo 欺骗 / 协议欺骗 / 路径穿越（明文与
// 百分号编码）/ 非 ASCII / 畸形。原「内网段全写法、仿冒域」类条目属
// 名单语义已随名单一起移除，不再拒绝。

import "testing"

func TestAdvWhitelistFuzzTable(t *testing.T) {
	reject := []string{
		// userinfo 欺骗（@ 一律拒绝，真实 host 与展示不符）
		"http://127.0.0.1:8799@xycovo.com/",
		// 控制字符 / CRLF / 制表
		"xycovo.com\nevil", "xycovo.com\revil", "xycovo.com\tevil", "xycovo.com\x00",
		"xycovo.com\r\nX-Injected: 1", "xycovo.com\x1b", "xycovo.com\x7f",
		// 超长
		string(make([]byte, 201)),
		"xycovo.com." + string(make([]byte, 190)),
		// 协议欺骗
		"ftp://xycovo.com", "gopher://xycovo.com", "file:///C:/Windows/win.ini",
		"javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=",
		// 路径穿越（明文与百分号编码）
		"http://xycovo.com/../admin", "http://xycovo.com/..%2f..%2fwin.ini",
		"http://127.0.0.1:8799/.%2e/.%2e/", "http://127.0.0.1:8799/%2E%2E/",
		"http://127.0.0.1:8799/real%2f..", "xycovo.com/..",
		// 非 ASCII / 全角 / RTLO / 中文句号
		"ｘycovo.com", "xycovo.com／evil", "xycovo。com", "xycovo‮moc.ovcy",
		// 畸形
		"", " ", ".", "..", "...", "/", "\\", "xycovo.com:0", "xycovo.com:99999",
		"xycovo.com:8799x", "xycovo.com:-1",
		// 裸 IPv6 / 带端口 IPv6 字面量（host:port 解析口径外，维持既有拒绝）
		"[::1]:8799", "::1",
	}
	for _, in := range reject {
		if _, err := Check(in); err == nil {
			t.Fatalf("应拒绝: %q", in)
		}
	}

	accept := []struct {
		in   string
		want string
	}{
		{"xycovo.com", "xycovo.com"},
		{"XYCOVO.COM", "xycovo.com"},
		{"xycovo.com.", "xycovo.com"},
		{"http://xycovo.com/", "xycovo.com"},
		{"https://xycovo.com", "xycovo.com"},
		{"47.100.49.228", "47.100.49.228"},
		{"127.0.0.1:8799", "127.0.0.1:8799"},
		{"http://127.0.0.1:8799/real", "127.0.0.1:8799"},
		// 仿冒域 / 陌生域：格式合法即放行（默认授权），去留由操作者判断
		{"xycovo.com.evil.com", "xycovo.com.evil.com"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
		{"192.168.88.137", "192.168.88.137"},
		{"169.254.169.254", "169.254.169.254"},
		// 已知等价归一（对抗记录 INFO）：尾冒号形态按无端口归一
		{"xycovo.com:", "xycovo.com"},
		{"xn--xycovo.com:", "xn--xycovo.com"},
		// 带端口归一
		{"10.0.0.5:8080", "10.0.0.5:8080"},
		{"example.com:443", "example.com:443"},
	}
	for _, c := range accept {
		got, err := Check(c.in)
		if err != nil {
			t.Fatalf("应放行 %q: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("Check(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
