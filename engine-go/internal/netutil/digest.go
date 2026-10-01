package netutil

import (
	"crypto/sha256"
	"fmt"
)

// hexDigestPrefix16 对原始字节做 sha256，取 hex 前 16 位。
// 对齐 Python hashlib.sha256(raw).hexdigest()[:16]（netutil.py:50/61）。
// fix1 安全门整改：SHA-1 已弃用（CWE-327），内容形态指纹改用 SHA-256 截断——
// 仅作页面形态比对（软 404 / catch-all 识别），两引擎同步迁移保持 parity。
// 用途是"页面形态指纹"（识别 SPA/网关 catch-all 假页，配合 baseline），
// 与 Python 版完全一致；不是口令存储/密钥派生，不承担加密保护职责。
func hexDigestPrefix16(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)[:16]
}
