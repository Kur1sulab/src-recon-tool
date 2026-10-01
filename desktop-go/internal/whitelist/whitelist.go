// Package whitelist 实现正点名单硬校验：名单外一切目标（含其他私网/环回端口）
// 一律拒绝。名单是用户明示授权的资产红线，宁严勿松。
package whitelist

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Entries 授权白名单（host 或 host:port，小写）。
// 127.0.0.1 仅放行 8799 端口（本机 mock 靶站 tests/mock_server.py）。
var Entries = []string{
	"xycovo.com",
	"47.100.49.228",
	"127.0.0.1:8799",
}

var errRejected = errors.New("目标不在授权白名单")

// Check 校验目标串（裸域名 / IP / host:port / http(s) URL），命中名单返回
// 归一化的 host[:port]，否则返回错误。任何解析失败都按拒绝处理。
func Check(target string) (string, error) {
	s := strings.TrimSpace(target)
	if s == "" || len(s) > 200 {
		return "", errRejected
	}
	// 控制字符 / 空白 / 非 ASCII 一律拒绝（URL 只认 ASCII 资产）
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r > 0x7e {
			return "", errRejected
		}
	}
	// 百分号编码的 . / % 按穿越嫌疑拒绝：路径段不做 URL 解码，
	// 字面 ".." 检查拦不住 %2e%2e 这类等价写法
	lower := strings.ToLower(s)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%25") {
		return "", errRejected
	}
	// 协议：只认 http/https，其余（ftp: 等）拒绝
	hasScheme := false
	for _, sch := range []string{"http://", "https://"} {
		if strings.HasPrefix(lower, sch) {
			s = s[len(sch):]
			hasScheme = true
			break
		}
	}
	if i := strings.Index(lower, "://"); i >= 0 && !hasScheme {
		return "", errRejected
	}
	// 用户信息（user@host）拒绝
	if strings.Contains(s, "@") {
		return "", errRejected
	}
	// 拆路径
	if i := strings.Index(s, "/"); i >= 0 {
		path := s[i:]
		if !hasScheme {
			// 裸域名/IP 不允许带路径（ip/admin 这类输入八成是手误）
			return "", errRejected
		}
		if strings.Contains(path, "..") {
			return "", errRejected
		}
		s = s[:i]
	}
	if s == "" {
		return "", errRejected
	}
	// 拆端口
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", errRejected // 非法端口
		}
	} else if strings.Count(s, ":") > 0 {
		return "", errRejected // IPv6 字面量或畸形 host:port，一律拒绝
	}
	if host == "" {
		return "", errRejected
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(host, "."), "."))
	if net.ParseIP(host) == nil {
		if !isDomain(host) {
			return "", errRejected
		}
	}
	key := host
	if port != "" {
		key = host + ":" + port
	}
	for _, w := range Entries {
		if w == key {
			return key, nil
		}
	}
	return "", fmt.Errorf("%w: %s", errRejected, key)
}

// isDomain 宽松域名格式校验：字母数字连字符标签，点分隔，无空标签。
func isDomain(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
				(r == '-' && i > 0 && i < len(label)-1)
			if !ok {
				return false
			}
		}
	}
	return true
}
