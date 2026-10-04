package engine

// fix1_extra_test.go — ValidateExtraArgs（按模块旗标精确白名单）单测：
// 堵 argparse 前缀缩写展开覆盖受控目标（--ur→--url last-wins）。

import "testing"

func TestValidateExtraArgs(t *testing.T) {
	ok := []struct {
		cmd   string
		extra []string
	}{
		{"portscan", nil},
		{"portscan", []string{"--ports", "1-100"}},
		{"portscan", []string{"--ports=80,443", "--timeout", "0.5", "--workers", "8"}},
		{"jsintel", []string{"--max-files", "5", "--workers=2"}},
		{"subdomain", []string{"--verify"}},
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
		{"jsintel", []string{"--dom", "evil.com"}, "跨模块缩写"},
		{"portscan", []string{"-t", "10.0.0.5"}, "短目标旗标"},
		{"portscan", []string{"--target=10.0.0.5"}, "长目标旗标"},
		{"portscan", []string{"--ports", "-u", "http://10.0.0.5/x"}, "取值位置注入旗标"},
		{"portscan", []string{"--ports=80", "--workers", "-4"}, "值以 - 开头"},
		{"icp", []string{"--verify"}, "跨模块旗标"},
		{"subdomain", []string{"junk"}, "游离值"},
		{"paths", []string{"--fast"}, "paths 子解析器无此旗标"},
		{"all", []string{"--workers", "4"}, "all 子解析器无可选项"},
	}
	for _, c := range bad {
		if err := ValidateExtraArgs(c.cmd, c.extra); err == nil {
			t.Fatalf("[%s] ValidateExtraArgs(%s, %v) 应拒绝", c.why, c.cmd, c.extra)
		}
	}
}

// TestBuildCmdArgsRejectsBadExtra：起进程前的最后一道闸必须生效。
func TestBuildCmdArgsRejectsBadExtra(t *testing.T) {
	if _, err := BuildCmdArgs("api", "http://127.0.0.1:8799/", []string{"--ur", "http://10.0.0.5/x"}); err == nil {
		t.Fatal("BuildCmdArgs 应拒绝缩写旗标注入")
	}
	if _, err := BuildCmdArgs("api", "http://127.0.0.1:8799/", []string{"--ports", "80"}); err == nil {
		t.Fatal("api 无 --ports 旗标，应拒绝")
	}
}
