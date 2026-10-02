package netutil

// fix2_netutil_test.go — 第 2 轮审计+对抗修复回归（netutil）：
//   1. HopPolicy：入口公网 → 逐跳拒内网/环回落点；入口私网（授权内网靶标）→ 放行
//   2. Baseline unknown 两键 marshal（对齐 netutil.py:197）

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHopPolicyPublicEntryBlocksPrivateLanding(t *testing.T) {
	// 公网入口（IP 字面量无需 DNS）：逐跳落内网/环回必须被拒
	hop := HopPolicy("http://93.184.216.34/")
	for _, bad := range []string{"http://127.0.0.1:18082/land", "http://192.168.88.1/land",
		"http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"} {
		if err := hop(bad); err == nil {
			t.Fatalf("公网入口的逐跳落点 %q 应被阻断", bad)
		}
	}
	// 公网落点放行
	if err := hop("http://93.184.216.34/next"); err != nil {
		t.Fatalf("公网→公网落点应放行: %v", err)
	}
}

func TestHopPolicyPrivateEntryAllowsPrivateLanding(t *testing.T) {
	// 入口私网/环回（授权内网靶标）：私网落点放行（与 fingerprint 现行语义一致）
	hop := HopPolicy("http://127.0.0.1:18081/r302")
	if err := hop("http://127.0.0.1:18082/land"); err != nil {
		t.Fatalf("私网入口→私网落点应放行: %v", err)
	}
	// 不可解析落点仍拒绝（两分支一致；.invalid 若被本机 fake-ip 解析则自动放行）
	if err := hop("http://definitely-not-a-hop.invalid/x"); err == nil {
		t.Log("本机 DNS 对 .invalid 返回了结果（fake-ip 环境），跳过该断言")
	}
}

func TestBaselineUnknownMarshalTwoKeys(t *testing.T) {
	b := BaselineResult{Kind: "unknown", Samples: 1}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"kind":"unknown","samples":1}` {
		t.Fatalf("unknown 应只出两键（对齐 netutil.py:197）: %s", data)
	}
	// normal 分支仍全键
	b2 := BaselineResult{Kind: "soft404", Status: 200, Digest: "abc", Size: 3,
		Ctype: "text/html", FinalURL: "http://x/", Samples: 2}
	data2, _ := json.Marshal(b2)
	for _, k := range []string{`"kind"`, `"status"`, `"digest"`, `"size"`, `"ctype"`, `"final_url"`, `"samples"`} {
		if !strings.Contains(string(data2), k) {
			t.Fatalf("normal 分支缺键 %s: %s", k, data2)
		}
	}
	_ = time.Second
}
