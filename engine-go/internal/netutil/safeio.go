package netutil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	unsafeNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	pathSepRe    = regexp.MustCompile(`[\\/]+`)
)

// SafeFilename 文件名白名单清洗，对齐 netutil.py:69-74：
// 只保留 [A-Za-z0-9._-]，其余换 _；截 64 字符；去首尾点号；空串回 unknown。
func SafeFilename(s string) string {
	s = unsafeNameRe.ReplaceAllString(s, "_")
	r := []rune(s)
	if len(r) > 64 {
		r = r[:64]
	}
	s = strings.Trim(string(r), ".")
	if s == "" {
		return "unknown"
	}
	return s
}

// SafeOutdir 输出目录纵深防御，对齐 netutil.py:114-128：
// 剔除 ../ 与 . 悬浮组件后再规范化使用（禁止目录穿越）；空串回 out。
func SafeOutdir(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		out = "out"
	}
	drive := filepath.VolumeName(out)
	tail := strings.TrimPrefix(out, drive)
	var parts []string
	for _, c := range pathSepRe.Split(tail, -1) {
		if c == "" || c == "." || c == ".." {
			continue
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return filepath.Join("out", "unknown")
	}
	var all []string
	switch {
	case drive != "":
		all = append([]string{drive + string(filepath.Separator)}, parts...)
	case strings.HasPrefix(out, "/") || strings.HasPrefix(out, "\\"):
		all = append([]string{string(filepath.Separator)}, parts...)
	default:
		all = parts
	}
	return filepath.Join(all...)
}

// withinBase 等价 Python os.path.commonpath([base, target]) == base 的包含判定。
func withinBase(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// SafeWrite 各模块落盘统一收口，对齐 netutil.py:147-163：
// out 先过 SafeOutdir，name 必须是纯文件名（再过 SafeFilename 白名单），
// 最终路径规范化后必须仍限于 out 内才写入 UTF-8。返回最终绝对路径。
func SafeWrite(out, name, content string) (string, error) {
	base, err := filepath.Abs(SafeOutdir(out))
	if err != nil {
		return "", err
	}
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("非法文件名: %q", name)
	}
	final := filepath.Join(base, SafeFilename(name))
	if !withinBase(base, final) {
		return "", fmt.Errorf("输出路径越界: %s", final)
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(final, []byte(content), 0o644); err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(final); err == nil {
		return abs, nil
	}
	return final, nil
}

// SafeSubdir 在 out 下构造多级子目录，对齐 netutil.py:131-144：
// 每一级都过 SafeFilename 白名单，最后包含校验仍限于 out 内才创建。
// 供证据目录 out/evidence/<host>/<slug>/ 这类外部可控多级拼接使用（c3 轮）。
func SafeSubdir(out string, parts ...string) (string, error) {
	base, err := filepath.Abs(SafeOutdir(out))
	if err != nil {
		return "", err
	}
	cur := base
	for _, p := range parts {
		cur = filepath.Join(cur, SafeFilename(p))
	}
	if !withinBase(base, cur) {
		return "", fmt.Errorf("输出路径越界: %s", cur)
	}
	if err := os.MkdirAll(cur, 0o755); err != nil {
		return "", err
	}
	return cur, nil
}
