package subdomain

// fix2b_test.go — 入口污点闸回归：形状非法的 domain 在 Run 入口即被拦截，
// 不得进入任何采集通道（OneForAll/crt.sh/certspotter/subfinder）。

import "testing"

func TestRunRejectsIllegalDomainShapes(t *testing.T) {
	// withStubs 未包：任何通道被触达都会打真实网络——断言 nil 即证明被入口拦截
	for _, d := range []string{
		"../evil",
		"a/b.com",
		`a\com`,
		"..",
		"a..com",
		"",
		"   ",
		"a.com\nevil",
	} {
		if got := Run(d, t.TempDir()); got != nil {
			t.Fatalf("Run(%q) 应被入口污点闸拦截返回 nil, 得 %v", d, got)
		}
	}
}
