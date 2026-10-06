package netutil

// urlcheck_hoppolicy_test.go — 终修轮 F4（审计 low）：HopPolicy 的 allowPrivate
// 推断收紧——只有「入口解析到私网/保留地址」才放行私网落点；入口 DNS 失败/
// 非法 URL 等其他成因一律从严（此前全部折算成放行信号，公网目标的重定向可
// 在 DNS 抖动窗口落私网）。零外网：127.0.0.1 字面量免 DNS，解析失败用保留
// TLD（.invalid，本地 resolver NXDOMAIN）。

import (
	"strings"
	"testing"
)

func TestHopPolicyAllowPrivateOnlyOnPrivateEntry(t *testing.T) {
	// 私网入口（IP 字面量免 DNS）→ 放行私网落点（授权内网靶语义不变）
	hop := HopPolicy("http://127.0.0.1:1/entry")
	if err := hop("http://127.0.0.1:2/next"); err != nil {
		t.Fatalf("私网入口应放行私网落点: %v", err)
	}

	// 入口解析失败 → 从严：私网落点必须拒绝（F4 修复点）。解析失败的确定性
	// 触发用 64 字节超长标签（resolver 客户端侧即报错、零网络、零查询）——
	// 不能用不存在域名：fake-ip DNS（198.18/15）对任意名都应答，会恰好落入
	// PrivateAddrError 分支（那是合法的放行路径，不是失败路径）。
	hopFail := HopPolicy("http://" + strings.Repeat("a", 64) + ".invalid/entry")
	if err := hopFail("http://127.0.0.1:2/next"); err == nil {
		t.Fatal("入口 DNS 解析失败不得被误判为私网入口（F4：策略在抖动窗口反转）")
	}

	// 非法 scheme 入口 → 从严
	hopBad := HopPolicy("ftp://127.0.0.1/entry")
	if err := hopBad("http://127.0.0.1:2/next"); err == nil {
		t.Fatal("非法 scheme 入口不得放行私网落点")
	}
}

func TestPrivateAddrErrorSentinel(t *testing.T) {
	_, err := CheckHTTPURL("http://127.0.0.1/x", false)
	pe, ok := err.(*PrivateAddrError)
	if !ok {
		t.Fatalf("私网阻断应返回 *PrivateAddrError（errors.As 可判）: %v", err)
	}
	if pe.Host != "127.0.0.1" {
		t.Errorf("Host 字段: %q", pe.Host)
	}
	// 用户可见文案保持原样（不因哨兵化而变化）
	if want := "目标 127.0.0.1 解析到内网/保留地址 127.0.0.1，已阻断（授权内网目标请显式 allow_private=True）"; pe.Error() != want {
		t.Errorf("文案漂移:\n got %q\nwant %q", pe.Error(), want)
	}
}
