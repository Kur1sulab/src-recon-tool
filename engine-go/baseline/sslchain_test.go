package baseline

// sslchain_test.go — TLS 证书链检查（§5.5）验收：
//   1. 本地造证书三类判定各命中（过期 / SAN 不匹配 / 自签），全程无外网。
//   2. 协议矩阵：本地 TLS 服务钳 MinVersion=1.2 时 1.0/1.1 判未启用。
//   4. 非 TLS 端口握手失败记「非 TLS 服务」，不按 error 级失败处理。
// 信任根经 sslRoots 注入（生产默认系统池），本地 CA 不进系统池也能完整建链。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// makeCA 本地测试 CA。
func makeCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// makeLeaf 用 CA 签发叶子证书；ca=nil 时自签。
func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, tpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := tpl
	signerKey := key
	if ca != nil {
		signer = ca
		signerKey = caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// leafTpl 叶子模板基础字段。
func leafTpl(notBefore, notAfter time.Time, dnsNames []string, ips []net.IP) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// startTLSServer 本地 TLS 服务（accept→握手→丢弃，调用方 Cleanup 关闭）。
func startTLSServer(t *testing.T, cert tls.Certificate, minVersion uint16) (addr string, stop func()) {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minVersion}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// withSSLRoots 注入信任根（含给定证书）并在测试结束还原。
func withSSLRoots(t *testing.T, certs ...*x509.Certificate) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	old := sslRoots
	sslRoots = func() *x509.CertPool { return pool }
	t.Cleanup(func() { sslRoots = old })
}

// withFastSSL 关闭协议矩阵间隔（测试提速）。
func withFastSSL(t *testing.T) {
	old := sslGap
	sslGap = 0
	t.Cleanup(func() { sslGap = old })
}

func TestSSLExpired(t *testing.T) {
	withFastSSL(t)
	ca, caKey := makeCA(t)
	withSSLRoots(t, ca)
	cert := makeLeaf(t, ca, caKey, leafTpl(time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), nil, []net.IP{net.ParseIP("127.0.0.1")}))
	addr, stop := startTLSServer(t, cert, tls.VersionTLS12)
	defer stop()
	port := strings.SplitN(addr, ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	if res.Error != "" {
		t.Fatalf("过期用例不应是模块级失败: %s", res.Error)
	}
	rows := res.Data["ports"].([]sslPortRow)
	if len(rows) != 1 {
		t.Fatalf("应 1 个端口行: %v", rows)
	}
	row := rows[0]
	if row.Cert == nil || row.Cert.RemainingDays >= 0 {
		t.Errorf("过期证书剩余天数应 <0: %+v", row.Cert)
	}
	if row.Verify.ChainOK || !strings.Contains(row.Verify.Reason, "过期") {
		t.Errorf("应判过期: %+v", row.Verify)
	}
	if row.SelfSigned {
		t.Error("CA 签发证书不应判自签")
	}
	found := false
	for _, r := range res.Risks {
		if r.Level == LevelFail && strings.Contains(r.Title, "过期") {
			found = true
		}
	}
	if !found {
		t.Errorf("应有过期 fail 风险: %+v", res.Risks)
	}
}

func TestSSLNameMismatch(t *testing.T) {
	withFastSSL(t)
	ca, caKey := makeCA(t)
	withSSLRoots(t, ca)
	// SAN 只含其他域名 → 对 127.0.0.1 校验不匹配
	cert := makeLeaf(t, ca, caKey, leafTpl(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []string{"other.example.test"}, nil))
	addr, stop := startTLSServer(t, cert, tls.VersionTLS12)
	defer stop()
	port := strings.SplitN(addr, ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	rows := res.Data["ports"].([]sslPortRow)
	if rows[0].Verify.ChainOK || !strings.Contains(rows[0].Verify.Reason, "不匹配") {
		t.Errorf("应判域名不匹配: %+v", rows[0].Verify)
	}
}

func TestSSLSelfSigned(t *testing.T) {
	withFastSSL(t)
	ca, _ := makeCA(t) // 只复用其证书进信任根；自签站单独造
	withSSLRoots(t, ca)
	cert := makeLeaf(t, nil, nil, func() *x509.Certificate {
		tpl := leafTpl(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []string{"127.0.0.1"}, []net.IP{net.ParseIP("127.0.0.1")})
		tpl.IsCA = true
		tpl.Subject.CommonName = "self-signed.test"
		return tpl
	}())
	addr, stop := startTLSServer(t, cert, tls.VersionTLS12)
	defer stop()
	port := strings.SplitN(addr, ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	rows := res.Data["ports"].([]sslPortRow)
	if !rows[0].SelfSigned {
		t.Errorf("应判自签: %+v", rows[0])
	}
}

func TestSSLValidChain(t *testing.T) {
	withFastSSL(t)
	ca, caKey := makeCA(t)
	withSSLRoots(t, ca)
	cert := makeLeaf(t, ca, caKey, leafTpl(time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), nil, []net.IP{net.ParseIP("127.0.0.1")}))
	addr, stop := startTLSServer(t, cert, tls.VersionTLS12)
	defer stop()
	port := strings.SplitN(addr, ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	rows := res.Data["ports"].([]sslPortRow)
	row := rows[0]
	if !row.Verify.ChainOK {
		t.Errorf("有效链应通过: %+v", row.Verify)
	}
	if row.SelfSigned || row.Cert == nil || row.Cert.RemainingDays <= 0 || row.Cert.SHA256 == "" {
		t.Errorf("证书面字段应齐全: %+v", row.Cert)
	}
	if res.Conclusion.Level != LevelOK {
		t.Errorf("有效链结论应 ok: %+v", res.Conclusion)
	}
}

func TestSSLProtocolMatrix(t *testing.T) {
	withFastSSL(t)
	ca, caKey := makeCA(t)
	withSSLRoots(t, ca)
	cert := makeLeaf(t, ca, caKey, leafTpl(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil, []net.IP{net.ParseIP("127.0.0.1")}))
	addr, stop := startTLSServer(t, cert, tls.VersionTLS12) // 钳 1.2 起
	defer stop()
	port := strings.SplitN(addr, ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	rows := res.Data["ports"].([]sslPortRow)
	mx := rows[0].Versions // map[string]bool
	if mx["TLS1.0"] || mx["TLS1.1"] {
		t.Errorf("MinVersion=1.2 的服务不应支持 1.0/1.1: %v", mx)
	}
	if !mx["TLS1.2"] || !mx["TLS1.3"] {
		t.Errorf("1.2/1.3 应支持: %v", mx)
	}
	// 旧协议启用 → warn 风险（本用例不启用，不应有）
	for _, r := range res.Risks {
		if strings.Contains(r.Title, "TLS1.0") || strings.Contains(r.Title, "TLS1.1") {
			t.Errorf("不应报旧协议风险: %+v", r)
		}
	}
}

func TestSSLNonTLS(t *testing.T) {
	withFastSSL(t)
	// 纯 TCP 服务（非 TLS）：握手必败，但按「非 TLS 服务」记录，Error 为空
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { buf := make([]byte, 512); _, _ = c.Read(buf); _ = c.Close() }()
		}
	}()
	defer func() { _ = ln.Close(); <-done }()
	port := strings.SplitN(ln.Addr().String(), ":", 2)[1]

	res := RunSSLChain(Options{Domain: "127.0.0.1", Ports: []string{port}, Logf: quietLogf})
	if res.Error != "" {
		t.Errorf("非 TLS 不应按 error 级失败: %s", res.Error)
	}
	rows := res.Data["ports"].([]sslPortRow)
	if rows[0].Reachable {
		t.Errorf("非 TLS 端口不应判可达: %+v", rows[0])
	}
	if !strings.Contains(rows[0].Note, "非 TLS") && !strings.Contains(rows[0].Note, "握手") {
		t.Errorf("应记非 TLS 服务: %q", rows[0].Note)
	}
}
