package whitelist

// fix1_whitelist_test.go — 对抗轮模糊表固化（fixesNeeded P3）：
// 把对抗实测的 90+ 用例按类别沉淀为核心子集，防白名单回归。类别：
// 仿冒域 / 内网段全写法（含整数与八进制、16 进制编码）/ 控制字符与 CRLF /
// 超长 / userinfo 欺骗 / 协议欺骗 / 路径穿越（明文与百分号编码）/ 非 ASCII。

import "testing"

func TestAdvWhitelistFuzzTable(t *testing.T) {
	reject := []string{
		// 仿冒域（后缀拼接 / 前缀拼接）
		"xycovo.com.evil.com", "exycovo.com", "xycovo.com.evil.cn", "xycovo-com.com",
		// 环回 / 私网 / 保留段的各种写法
		"127.0.0.1", "127.0.0.1:80", "127.0.0.1:8798", "localhost", "localhost:8799",
		"[::1]:8799", "::1", "0.0.0.0", "0177.0.0.1", "2130706433", "0x7f000001",
		"127.1", "192.168.88.137", "10.0.0.1", "172.16.0.1", "169.254.169.254",
		"198.18.0.1", "100.64.0.1", "224.0.0.1", "255.255.255.255",
		"http://127.0.0.1:8799@xycovo.com/", // userinfo 欺骗（真实 host 是环回前的假象）
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
		"xycovo.com:8799x", "xn--xycovo.com:", "xycovo.com:-1",
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
		// 已知等价归一（对抗记录 INFO）：尾冒号形态等价放行为名单内资产，
		// 非绕过；显式拒绝属可选收紧，本轮不改行为，仅在此钉住现状。
		{"xycovo.com:", "xycovo.com"},
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
