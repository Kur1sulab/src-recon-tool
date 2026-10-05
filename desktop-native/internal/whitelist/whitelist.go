// Package whitelist 实现目标串卫生校验与归一化：控制字符/协议/端口/路径穿越
// 等格式问题一律拒绝；目标本身全部默认授权（用户裁定 2026-10-05），本包不再
// 做任何名单成员判定。
package whitelist

import (
	"errors"
	"net"
	"strings"
)

var errRejected = errors.New("目标格式不合法")

// Check 校验目标串（裸域名 / IP / host:port / http(s) URL）的格式卫生并归一化，
// 返回小写 host[:port] key。任何解析失败都按拒绝处理；目标本身全部默认授权。
func Check(target string) (string, error) {
	s := strings.TrimSpace(target)
	if s == "" || len(s) > 200 {
		return "", errRejected
	}
	// 内嵌控制字符 / 非 ASCII 一律拒绝（URL 只认 ASCII 资产）。
	// 口径对齐（终修轮 P4）：壳层 CreateTask 会先 strings.TrimSpace（含
	// \v \f NBSP 等 Unicode 空白）再进本闸——首尾空白由壳的粘贴体验
	// 契约归一，归一后仍是名单内主机、无越闸面；本闸把守的是「内嵌
	// 控制字符」与「非 ASCII」，两层职责以本注释为界。
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
		if strings.Contains(host, ":") {
			return "", errRejected // IPv6 字面量暂不支持（格式口径，非授权限制）
		}
		if port != "" {
			pn, lerr := net.LookupPort("tcp", port)
			if lerr != nil || pn == 0 {
				return "", errRejected // 非法端口或 0 端口（0 是保留值，不是可探测目标）
			}
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
	return key, nil
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
