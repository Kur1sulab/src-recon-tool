package netutil

import (
	"crypto/sha1"
	"fmt"
)

// hexDigestPrefix16 对原始字节做 sha1，取 hex 前 16 位。
// 对齐 Python hashlib.sha1(raw).hexdigest()[:16]（netutil.py:50/61）。
// 用途是"页面形态指纹"（识别 SPA/网关 catch-all 假页，配合 baseline），
// 与 Python 版完全一致；不是口令存储/密钥派生，不承担加密保护职责。
func hexDigestPrefix16(b []byte) string {
	sum := sha1.Sum(b)
	return fmt.Sprintf("%x", sum)[:16]
}
