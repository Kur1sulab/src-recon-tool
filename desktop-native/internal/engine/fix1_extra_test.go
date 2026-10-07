package engine

// fix1_extra_test.go — 附加参数精确白名单回归（堵 argparse 前缀缩写展开覆盖
// 受控目标，--ur→--url last-wins）。第 2 步（直调重写）收缩：jsintel/portscan
// 退役后从 moduleFlags 表移除；ValidateExtraArgs 对表外子命令返回 nil 的契约
// 不变（子命令合法性由 cmdSet/Start 把关）。

import "testing"

func TestValidateExtraArgs(t *testing.T) {
	ok := []struct {
		cmd   string
		extra []string
	}{
		{"all", nil},
		{"paths", nil},
		{"api", nil},
		{"fingerprint", nil},
		{"reverse", nil},
		{"icp", nil},
		{"subdomain", []string{"--verify"}},
		{"baseline", []string{"--checks", "secheaders"}},
		{"baseline", []string{"--checks=secheaders,dnsrec"}},
	}
	for _, c := range ok {
		if err := ValidateExtraArgs(c.cmd, c.extra); err != nil {
			t.Fatalf("ValidateExtraArgs(%s, %v) 不应拒绝: %v", c.cmd, c.extra, err)
		}
	}
	bad := []struct {
		cmd   string
		extra []string
		why   string
	}{
		{"api", []string{"-ur", "http://10.0.0.5/x"}, "argparse 前缀缩写展开覆盖目标"},
		{"api", []string{"--ur=http://10.0.0.5/x"}, "缩写 = 形态"},
		{"fingerprint", []string{"--u", "http://10.0.0.5/x"}, "单字符缩写"},
		{"icp", []string{"--dom", "evil.com"}, "跨模块缩写"},
		{"icp", []string{"--verify"}, "跨模块旗标"},
		{"subdomain", []string{"junk"}, "游离值"},
		{"paths", []string{"--fast"}, "paths 子解析器无此旗标"},
		{"all", []string{"--workers", "4"}, "all 子解析器无可选项"},
		{"baseline", []string{"--verify"}, "跨模块 store_true 旗标"},
	}
	for _, c := range bad {
		if err := ValidateExtraArgs(c.cmd, c.extra); err == nil {
			t.Fatalf("[%s] ValidateExtraArgs(%s, %v) 应拒绝", c.why, c.cmd, c.extra)
		}
	}
}

// 退役契约：jsintel/portscan 不在表内 → ValidateExtraArgs 放行（nil），
// 但 CmdAllowed=false → Start 就地拒绝。两层职责以此测试钉住。
func TestValidateExtraArgsRetiredModulesPassThrough(t *testing.T) {
	if err := ValidateExtraArgs("jsintel", []string{"--max-files", "5"}); err != nil {
		t.Fatalf("表外子命令应放行交 cmdSet 把关: %v", err)
	}
	if err := ValidateExtraArgs("portscan", nil); err != nil {
		t.Fatalf("表外子命令应放行交 cmdSet 把关: %v", err)
	}
	if CmdAllowed("jsintel") || CmdAllowed("portscan") {
		t.Fatal("退役模块不得仍在 cmdSet")
	}
}
