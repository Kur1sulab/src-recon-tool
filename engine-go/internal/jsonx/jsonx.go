// Package jsonx：JSON 序列化小工具。
// 目标是对齐 Python json.dumps(..., ensure_ascii=False, indent=2)：
//   - 非 ASCII 字符直接输出 UTF-8（Go 默认会转义 <>&，必须关掉）；
//   - 末尾不带换行（Python json.dumps 不带，Go json.Encoder.Encode 自带一个）。
package jsonx

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Pretty 输出缩进 2 的 JSON 文本（无 HTML 转义、无末尾换行）。
func Pretty(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// Compact 输出单行 JSON（无 HTML 转义、无末尾换行）。
func Compact(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}
