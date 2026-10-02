package netutil

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Python 3.8 ipaddress 的 is_private ∪ is_loopback ∪ is_link_local ∪ is_reserved
// 全集（netutil.py:106-110 的阻断集合）。注意 Go 标准库 net.IP.IsPrivate 只覆盖
// RFC1918，缺 198.18.0.0/15（Clash fake-ip 段，本机高频命中）、0.0.0.0/8、
// 192.0.0.0/29、198.51.100.0/24、203.0.113.0/24、240.0.0.0/4 等——必须自实现，
// 单测用动态 python 探针逐 IP 对照钉死。
//
// IPv4：Python 3.8 _private_networks 全 14 段（loopback/linklocal/reserved 均已
// 包含其中，无需单列）。
// IPv6：3.8 私有+保留并集 {::/8, 100::/8, 2001::/23, 2001:db8::/32, fc00::/7,
// fe80::/10}——::/8 已覆盖 ::/128、::1/128、::ffff:0:0/96；100::/8 已覆盖
// 100::/64。注意 2001:db8::/32 是 3.8 特有（同列 private 与 reserved，探针实证）。
var (
	v4Blocked = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/29", "192.0.0.170/31", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "255.255.255.255/32",
	)
	v6Blocked = mustPrefixes("::/8", "100::/8", "2001::/23", "2001:db8::/32", "fc00::/7", "fe80::/10")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p := netip.MustParsePrefix(s)
		ps = append(ps, p)
	}
	return ps
}

// isExplicitV6Literal：URL host 本身是否显式 IPv6 字面量（含 ":"）。
// Python 侧对显式 "::ffff:x.x.x.x" 输入按 IPv6Address 判（私网命中），
// 对 v4 输入/DNS A 记录按 IPv4Address 判——以此区分 Go 解析器的 4-in-6 伪影。
func isExplicitV6Literal(host string) bool {
	return strings.Contains(host, ":")
}

// ipBlocked 等价 Python: ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
func ipBlocked(a netip.Addr) bool {
	list := v4Blocked
	if !a.Is4() {
		list = v6Blocked
	}
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckHTTPURL 请求前 URL 边界校验（SSRF 纪律），对齐 netutil.py:77-111：
//  1. 只放行 http/https 且必须有主机；
//  2. 解析主机并检查 IP 边界，默认阻断私网/环回/链路本地/保留地址；
//     allowPrivate=true 显式放行（授权内网/本机靶标是合法目标）。
//
// 校验通过原样返回 URL；非法或越界返回 error。
func CheckHTTPURL(rawURL string, allowPrivate bool) (string, error) {
	u := strings.TrimSpace(rawURL)
	p, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("非法 URL: %q", trunc(u, 80))
	}
	if (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return "", fmt.Errorf("非法探测目标（仅允许 http/https 远程地址）: %q", trunc(u, 80))
	}
	host := p.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL 缺少主机名: %q", trunc(u, 80))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("目标主机无法解析: %s", host)
	}
	if !allowPrivate {
		for _, a := range addrs {
			ap, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			// 关键语义对齐：Go 解析器对 v4 字面量/A 记录可能返回 4-in-6 形式
			//（net.ParseIP 恒 16 字节），而 Python getaddrinfo 对 v4 一律返回
			// 点分字符串 → IPv4Address。这里 unmap 还原为 v4 再判定，
			// 否则 8.8.8.8 会被 ::/8 误伤（单测实测踩中）。
			// 显式书写 "::ffff:x.x.x.x" 的场景仍按 IPv6 判（见 ipBlocked 探针测试）。
			if ap.Is4In6() && !isExplicitV6Literal(host) {
				ap = ap.Unmap()
			}
			if ipBlocked(ap) {
				return "", fmt.Errorf("目标 %s 解析到内网/保留地址 %s，已阻断（授权内网目标请显式 allow_private=True）",
					host, a.IP.String())
			}
		}
	}
	return u, nil
}

// HopPolicy 返回与入口 URL 授权语义一致的逐跳重定向校验回调（fix2 P1）：
//   - 入口是公网可解析目标（CheckHTTPURL 默认边界校验通过）→ 逐跳拒绝
//     内网/环回/保留/链路本地落点——堵「授权公网目标的 302 把探测流量
//     （可能含凭据 query）打进未授权内网段/云元数据地址」；
//   - 入口本身私网/环回（授权内网靶标，本工具的合法场景）或无法解析 →
//     逐跳只做协议白名单 + 可解析性校验，私网落点放行——与
//     fingerprint/PickBase 现行 allowPrivate=true 语义一致。
//
// 注意：本回调只约束重定向落点，入口自身的边界策略由调用方决定。
func HopPolicy(entryURL string) func(string) error {
	_, entryErr := CheckHTTPURL(entryURL, false)
	allowPrivate := entryErr != nil
	return func(next string) error {
		_, err := CheckHTTPURL(next, allowPrivate)
		return err
	}
}
