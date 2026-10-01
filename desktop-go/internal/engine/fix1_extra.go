package engine

// fix1_extra.go — 第 1 轮修复补充（修缮工复审新增）：
// server 层的 targetFlagTokens 黑名单挡住了目标旗标的精确形态，但 argparse
// 默认允许前缀缩写（allow_abbrev=True）——`--ur http://evil` 会在 Python 侧
// 展开成 --url 并按 last-wins 覆盖受控目标，黑名单按精确名匹配拦不住。
// 这里在起进程前的最后一道闸（BuildCmdArgs）加「按模块精确白名单」：
// 长旗标必须与 recon.py 子解析器定义全名一致，缩写/未知/跨模块旗标一律拒绝。

import (
	"fmt"
	"strings"
)

// moduleFlags 各子命令允许用户附加的旗标白名单（与 recon.py:164-187 子解析器
// 一一对应）。all/paths/api/fingerprint/reverse/icp 的子解析器除目标旗标外
// 无可选项，故为空集。
var moduleFlags = map[string]map[string]bool{
	"all":         {},
	"paths":       {},
	"api":         {},
	"fingerprint": {},
	"reverse":     {},
	"icp":         {},
	"jsintel":     {"--max-files": true, "--workers": true},
	"portscan":    {"--ports": true, "--timeout": true, "--workers": true},
	"subdomain":   {"--verify": true},
}

// valueFlags 需要取值的旗标（store_true 类除外）；值 token 不允许以 "-" 开头。
var valueFlags = map[string]bool{
	"--ports": true, "--timeout": true, "--workers": true, "--max-files": true,
}

// ValidateExtraArgs 校验用户附加参数（fix1 P0 纵深层）。规则：
//   - token 以 "-" 开头：必须是该子命令白名单内的长旗标全名（--name 或 --name=value），
//     缩写（--ur/--dom）、短旗标（-u）、跨模块旗标一律拒绝——封 argparse
//     前缀缩写展开的 last-wins 目标覆盖；
//   - --name=value 的 value 不得以 "-" 开头（堵 --ports -u 形态的歧义注入）；
//   - 取值旗标后的下一个 token 视为值，同样不得以 "-" 开头；
//   - 游离值 token 拒绝（子命令无位置参数，到 Python 侧必然 unrecognized arguments）。
func ValidateExtraArgs(cmd string, extra []string) error {
	allowed, ok := moduleFlags[cmd]
	if !ok {
		return nil // 子命令合法性由 BuildCmdArgs 的 cmdSet 把关
	}
	expectValue := false
	for _, tk := range extra {
		if strings.HasPrefix(tk, "-") {
			if expectValue {
				return fmt.Errorf("旗标取值不允许以 - 开头: %s", tk)
			}
			name := tk
			if i := strings.IndexByte(tk, '='); i >= 0 {
				name = tk[:i]
				if strings.HasPrefix(tk[i+1:], "-") {
					return fmt.Errorf("旗标取值不允许以 - 开头: %s", tk)
				}
			}
			if !allowed[name] {
				return fmt.Errorf("该子命令不允许的旗标: %s", name)
			}
			expectValue = valueFlags[name] && !strings.Contains(tk, "=")
			continue
		}
		if !expectValue {
			return fmt.Errorf("游离参数不允许: %s", tk)
		}
		expectValue = false
	}
	return nil
}
