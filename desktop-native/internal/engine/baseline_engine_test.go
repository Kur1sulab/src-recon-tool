package engine

// baseline_engine_test.go — baseline 模块直调接线（第二子进程 recon-go.exe 已退役）：
// 基线检查在桌面进程内直调 engine-go baseline.RunContext，与 engine-go cli.go
// baseline 分支同参（Domain/URL=PickBase/Out/Checks/--checks 归一化/AllowPrivate/
// Emit 直通 sink/Logf 静默）。

import (
	"errors"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/baseline"
)

func TestCmdAllowedBaseline(t *testing.T) {
	if !CmdAllowed("baseline") {
		t.Fatal("baseline 应在八模块白名单内")
	}
}

func TestValidateExtraArgsBaseline(t *testing.T) {
	// 放行：--checks 是 baseline 唯一附加旗标（取值型）
	if err := ValidateExtraArgs("baseline", []string{"--checks", "secheaders"}); err != nil {
		t.Fatalf("--checks 应放行: %v", err)
	}
	if err := ValidateExtraArgs("baseline", []string{"--checks=secheaders,dnsrec"}); err != nil {
		t.Fatalf("--checks= 应放行: %v", err)
	}
	// 拒绝：取值旗标挂尾 / 缩写 / 跨模块旗标 / 游离值
	for _, extra := range [][]string{
		{"--checks"},
		{"--check", "secheaders"},
		{"--verify"},
		{"-d", "evil.com"},
		{"secheaders"},
		{"--checks", "-d"},
	} {
		if err := ValidateExtraArgs("baseline", extra); err == nil {
			t.Fatalf("extra %v 应拒绝", extra)
		}
	}
}

// buildBaselineOptions 参数组装（纯函数）：--checks 归一化、AllowPrivate 恒开
// （桌面契约：授权内网目标放行）、Out 直传。
func TestBuildBaselineOptions(t *testing.T) {
	// 缺省 = 全部 8 项
	o, err := buildBaselineOptions("xycovo.com", nil, `C:\out\x`)
	if err != nil {
		t.Fatalf("缺省 checks: %v", err)
	}
	if len(o.Checks) != 8 {
		t.Fatalf("缺省应全 8 项，得 %v", o.Checks)
	}
	if o.Domain != "xycovo.com" || o.Out != `C:\out\x` {
		t.Fatalf("Domain/Out 应直传: %+v", o)
	}
	if !o.AllowPrivate {
		t.Fatal("AllowPrivate 应恒开（与 cli.go:387 同参）")
	}
	// --checks 值形态
	o, err = buildBaselineOptions("xycovo.com", []string{"--checks", "secheaders,webfiles"}, "")
	if err != nil {
		t.Fatalf("--checks 值形态: %v", err)
	}
	if len(o.Checks) != 2 || o.Checks[0] != "secheaders" || o.Checks[1] != "webfiles" {
		t.Fatalf("checks 归一化不符: %v", o.Checks)
	}
	// --checks= 等号形态
	o, err = buildBaselineOptions("xycovo.com", []string{"--checks=sslchain"}, "")
	if err != nil {
		t.Fatalf("--checks= 形态: %v", err)
	}
	if len(o.Checks) != 1 || o.Checks[0] != "sslchain" {
		t.Fatalf("checks 等号形态不符: %v", o.Checks)
	}
	// 未知名 → ErrUnknownCheck（零网络副作用先拒绝）
	if _, err := buildBaselineOptions("xycovo.com", []string{"--checks", "nope"}, ""); !errors.Is(err, baseline.ErrUnknownCheck) {
		t.Fatalf("未知检查名应报 ErrUnknownCheck，得 %v", err)
	}
}
