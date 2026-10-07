package baseline

// helpers_test.go — 测试共享工具：真实 RSA 公钥构造（mailsec/dnsrec 用例）。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// jsonUnmarshal 测试用 JSON 字符串解码（whois/rdap fixture）。
func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

// b64Pub 生成 bits 位 RSA 公钥的 base64 DER（DKIM p= 形态）。
func b64Pub(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("生成 RSA-%d 密钥失败: %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
