// sslchain.go — TLS 证书链检查（报告 §5.5）：tls.DialWithDialer（10s 超时）
// 取证书链（握手期不校验，取证后再验），证书面（剩余天数/CN/SAN/签发者/SHA256）、
// 建链判定（x509.Verify + 系统根池——本地测试经 sslRoots 注入；自签/过期/
// 域名不匹配/链不完整各独立原因）、协议矩阵（Min/Max 钳位 4 次握手，串行+间隔
// 控噪）。默认 443，Options.Ports 扩展。非 TLS 端口记「非 TLS 服务」不按失败处理。
// 注意：本模块是显式证书信息收集（验证语义），与 fetch 探测通道的免校验语义
// （netutil，内容探测）是两回事——这里握手期免校验只为拿到无效证书的链。
package baseline

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
)

// sslRoots 建链验证根池（nil = 系统池；本地测试注入含测试 CA 的池）。
var sslRoots = func() *x509.CertPool { return nil }

// sslGap 协议矩阵两次握手间隔（§5.5 串行+间隔控噪；测试置 0）。
var sslGap = 200 * time.Millisecond

// sslVersions 协议矩阵（§5.5：四档钳位）。
// 注：枚举含 TLS1.0/1.1 是检查本体（探测目标是否误启旧协议并给出 warn 风险），
// 客户端钳位只为握手探测，不代表本工具的传输策略降级；Mimosa 提示已知并有意保留。
var sslVersions = []struct {
	name string
	ver  uint16
}{
	{"TLS1.0", tls.VersionTLS10},
	{"TLS1.1", tls.VersionTLS11},
	{"TLS1.2", tls.VersionTLS12},
	{"TLS1.3", tls.VersionTLS13},
}

// sslCertFace 证书面。
type sslCertFace struct {
	SubjectCN     string   `json:"subject_cn"`
	IssuerCN      string   `json:"issuer_cn"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	RemainingDays int      `json:"remaining_days"`
	DNSNames      []string `json:"dns_names"`
	SHA256        string   `json:"sha256"`
}

// sslVerifyRow 建链判定。
type sslVerifyRow struct {
	ChainOK bool   `json:"chain_ok"`
	Reason  string `json:"reason"` // 通过 / 已过期 / 域名不匹配 / 信任链不完整（或自签）
}

// sslPortRow 单端口结果。
type sslPortRow struct {
	Port       string          `json:"port"`
	Reachable  bool            `json:"reachable"`
	Note       string          `json:"note,omitempty"`
	Cert       *sslCertFace    `json:"cert,omitempty"`
	Verify     sslVerifyRow    `json:"verify"`
	SelfSigned bool            `json:"self_signed,omitempty"`
	Versions   map[string]bool `json:"versions,omitempty"`
}

// classifyVerify 建链判定分类（独立布尔+原因，§5.5）。
func classifyVerify(err error) sslVerifyRow {
	if err == nil {
		return sslVerifyRow{ChainOK: true, Reason: "通过"}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate has expired") || strings.Contains(msg, "expired"):
		return sslVerifyRow{Reason: "证书已过期"}
	case strings.Contains(msg, "certificate is valid for") || strings.Contains(msg, "doesn't contain any IP SANs"):
		return sslVerifyRow{Reason: "域名不匹配（SAN 未覆盖目标）"}
	case strings.Contains(msg, "signed by unknown authority"):
		return sslVerifyRow{Reason: "信任链不完整（系统根不可达，常见于自签/私有 CA）"}
	default:
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return sslVerifyRow{Reason: msg}
	}
}

// sslCertFaceFrom 证书 → 证书面。
func sslCertFaceFrom(cert *x509.Certificate, now time.Time) *sslCertFace {
	sum := sha256.Sum256(cert.Raw)
	dnsNames := cert.DNSNames
	if dnsNames == nil {
		dnsNames = []string{}
	}
	return &sslCertFace{
		SubjectCN:     cert.Subject.CommonName,
		IssuerCN:      cert.Issuer.CommonName,
		NotBefore:     cert.NotBefore.Format("2006-01-02"),
		NotAfter:      cert.NotAfter.Format("2006-01-02"),
		RemainingDays: int(cert.NotAfter.Sub(now).Hours() / 24),
		DNSNames:      dnsNames,
		SHA256:        hex.EncodeToString(sum[:]),
	}
}

// probePort 一次握手取证书链 + 建链判定 + 自签判定。
func probePort(host, port string, timeout time.Duration) sslPortRow {
	row := sslPortRow{Port: port}
	dialer := &net.Dialer{Timeout: timeout}
	// 证书取证配置（免校验策略单点在 netutil.ProbeTLSConfig）：先拿到无效
	// 证书的链，建链判定在下方 x509.Verify 显式执行
	conf := netutil.ProbeTLSConfig(host, 0, 0)
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), conf)
	if err != nil {
		row.Note = sslDialNote(err)
		return row
	}
	defer conn.Close()
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		row.Reachable = true
		row.Note = "服务端未出示证书"
		return row
	}
	row.Reachable = true
	now := nowFn()
	row.Cert = sslCertFaceFrom(certs[0], now)
	// 自签：链仅 1 张且 Issuer==Subject（Raw 字节比较）
	row.SelfSigned = len(certs) == 1 && string(certs[0].RawIssuer) == string(certs[0].RawSubject)
	// 建链判定（根池默认系统池）
	vopts := x509.VerifyOptions{DNSName: host}
	if pool := sslRoots(); pool != nil {
		vopts.Roots = pool
	}
	_, verr := certs[0].Verify(vopts)
	row.Verify = classifyVerify(verr)
	return row
}

// sslDialNote 握手失败归类（非 TLS 服务 vs 连接失败，§5.5 验收）。
func sslDialNote(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "first record does not look like a TLS"),
		strings.Contains(msg, "protocol version not supported"), strings.Contains(msg, "no protocols supported"),
		strings.Contains(msg, "handshake failure"):
		return "非 TLS 服务（TLS 握手被拒/非 TLS 协议）"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒（端口未开放）"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "timeout"):
		return "连接超时"
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return "握手失败：" + msg
}

// probeVersions 协议矩阵：四档 Min/Max 钳位各拨一次（串行 + sslGap 间隔）。
func probeVersions(host, port string, timeout time.Duration) map[string]bool {
	out := map[string]bool{}
	for i, v := range sslVersions {
		if i > 0 {
			time.Sleep(sslGap)
		}
		dialer := &net.Dialer{Timeout: timeout}
		// 协议矩阵只测目标对某版本的支持（探测语义配置同上，单点 netutil）
		conf := netutil.ProbeTLSConfig(host, v.ver, v.ver)
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), conf)
		if err == nil {
			out[v.name] = true
			conn.Close()
		} else {
			out[v.name] = false
		}
	}
	return out
}

// RunSSLChain TLS 证书链检查主流程（§5.5）。
func RunSSLChain(o Options) Result {
	res := NewResult(CheckSSLChain, o.Domain, "")
	ports := o.Ports
	if len(ports) == 0 {
		ports = []string{"443"}
	}
	rows := []sslPortRow{}
	for _, p := range ports {
		row := probePort(o.Domain, p, 10*time.Second)
		// 协议矩阵只对首端口做（§5.5 控噪：串行 + 间隔，4 次握手）
		if row.Reachable && p == ports[0] {
			row.Versions = probeVersions(o.Domain, p, 10*time.Second)
			for _, name := range []string{"TLS1.0", "TLS1.1"} {
				if row.Versions[name] {
					res.Risks = append(res.Risks, Risk{Level: LevelWarn,
						Title: name + " 旧协议仍启用", Detail: "已知可降级攻击面，建议关闭"})
				}
			}
		}
		rows = append(rows, row)
	}

	worst := LevelOK
	warns := 0
	for _, row := range rows {
		if !row.Reachable {
			warns++
			res.Risks = append(res.Risks, Risk{Level: LevelInfo, Title: fmt.Sprintf("端口 %s：%s", row.Port, row.Note)})
			continue
		}
		c := row.Cert
		if c != nil {
			if c.RemainingDays < 0 {
				res.Risks = append(res.Risks, Risk{Level: LevelFail,
					Title: fmt.Sprintf("证书已过期 %d 天（端口 %s）", -c.RemainingDays, row.Port), Detail: "NotAfter " + c.NotAfter})
				worst = LevelFail
			} else if c.RemainingDays < 30 {
				res.Risks = append(res.Risks, Risk{Level: LevelWarn,
					Title: fmt.Sprintf("证书 %d 天后到期（端口 %s）", c.RemainingDays, row.Port), Detail: "NotAfter " + c.NotAfter})
				warns++
			}
		}
		if row.SelfSigned {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn, Title: fmt.Sprintf("自签证书（端口 %s）", row.Port)})
			warns++
		}
		if !row.Verify.ChainOK && !row.SelfSigned {
			res.Risks = append(res.Risks, Risk{Level: LevelWarn,
				Title: fmt.Sprintf("建链未通过（端口 %s）", row.Port), Detail: row.Verify.Reason})
			warns++
		}
	}
	if warns > 0 && worst == LevelOK {
		worst = LevelWarn
	}
	// 非 TLS 端口不按 error 级失败处理（§5.5）：Error 恒空，done 事件
	res.Data["ports"] = rows
	res.Data["summary"] = []string{fmt.Sprintf("端口 %s：%d 个探测点", strings.Join(ports, "/"), len(rows))}
	res.Conclusion = Conclusion{Level: worst, Text: fmt.Sprintf("%d 个端口，证书面/建链/协议矩阵完成（风险 %d 条）", len(rows), len(res.Risks))}
	return res
}
