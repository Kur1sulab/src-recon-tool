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

// winReservedStems Windows 保留设备名主干（大小写不敏感；带任意扩展名同样保留，
// 如 con.txt / COM1.zip 在老版 Windows 会劫持到设备）。fix1（对抗 P2）：
// SafeFilename 白名单原样放行这些名字，命中后在主干后补 _ 规避。
var winReservedStems = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// DefuseWindowsReservedStem 若 s 的主干（首个 '.' 之前的部分，大小写不敏感）
// 是 Windows 保留设备名（con/prn/aux/nul/com1-9/lpt1-9），在主干后补 "_" 规避；
// 否则原样返回。供 SafeFilename 与 MakeOutdir/outDirFor（目录名同规则）共用。
func DefuseWindowsReservedStem(s string) string {
	stem, ext := s, ""
	if i := strings.Index(s, "."); i >= 0 {
		stem, ext = s[:i], s[i:]
	}
	if winReservedStems[strings.ToLower(stem)] {
		return stem + "_" + ext
	}
	return s
}

// SafeFilename 文件名白名单清洗，对齐 netutil.py:69-74：
// 只保留 [A-Za-z0-9._-]，其余换 _；截 64 字符；去首尾点号；空串回 unknown。
// fix1 P2：Windows 保留设备名主干（con/nul/aux/com1-9/lpt1-9，任意扩展名组合）
// 命中则在主干后补 _（con.txt → con_.txt），与 Python safe_filename 同步加固。
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
	return DefuseWindowsReservedStem(s)
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
