// Package netutil 是 Python 引擎 src/modules/netutil.py 的 Go 移植：
// 统一 HTTP 请求底座（fetch）+ URL 边界校验（check_http_url）+ 安全落盘
// （safe_filename/safe_outdir/safe_write/safe_subdir）+ 软 404 基线
// （baseline/is_baseline/same_shape）+ 存活复验（verify_live）。
// 语义逐字段对齐 Python 版，parity 测试钉死行为。
//
// 安全说明：本包是授权测试工具的探测底座——
//   - TLS 策略见 tlsProbeConfig()：被扫目标常见自签/过期证书，
//     与 Python 版 ssl.CERT_NONE 语义一致（内容探测，不做身份认证/传密）；
//   - shortDigest 是页面形态指纹（识别 catch-all 假页），与 Python
//     hashlib.sha256(...).hexdigest()[:16] 一致，非口令/密钥保护用途。
package netutil

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultUA 对齐 netutil._UA。
const DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) src-recon-tool/1.0"

// FetchOpt 对齐 netutil.fetch 的参数；零值字段取 Python 默认值。
type FetchOpt struct {
	Timeout  time.Duration // Python 默认 12s
	Follow   bool          // Python 默认 True（跟随重定向）
	MaxBytes int           // Python 默认 200000
	Method   string        // 空 = GET；带 Data 且未指定时自动 POST（urllib 语义）
	Data     []byte
	Headers  map[string]string
	// HopCheck（fix1 P1，Go 侧加固）：Follow 模式下每一跳重定向目标在跟随之先
	// 过本回调，返回 error 即中止跟随、该请求按失败处理。nil = 不做逐跳校验
	// （默认，与 Python 侧现状一致，parity 不受影响）。入口做过 CheckHTTPURL
	// 的调用方（fingerprint/PickBase）应传入同策略回调，堵「入口校验不约束
	// 302 落点」的边界盲区。可观测行为与 Python 保持一致：Python 对解析失败
	// 的重定向目标同样请求失败（error 字段），跨 scheme 重定向两侧协议栈都拒绝。
	HopCheck func(nextURL string) error
}

// Result 与 Python fetch 返回 dict 逐字段对齐（JSON 键名一致）。
// status 在请求失败时 Python 为 null、Go 为 0，parity 断言只比成功路径。
type Result struct {
	OK       bool              `json:"ok"`
	URL      string            `json:"url"`
	Status   int               `json:"status"`
	FinalURL string            `json:"final_url"`
	Size     int               `json:"size"`
	Digest   string            `json:"digest"`
	Ctype    string            `json:"ctype"`
	Body     string            `json:"body"`
	Headers  map[string]string `json:"headers"`
	Err      string            `json:"error,omitempty"`
}

// trunc 按字符截断（Python str[:n] 按字符计数）。
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// decodeUTF8Ignore 等价 Python bytes.decode("utf-8", "ignore")：非法字节直接丢弃。
func decodeUTF8Ignore(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			b = b[1:]
			continue
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// tlsProbeConfig 返回探测用 TLS 配置（语义对齐 Python ctx.verify_mode = CERT_NONE）。
// 这是授权测试工具的固有语义：被扫目标普遍存在自签/过期证书，若强校验则
// 全部 HTTPS 目标直接握手失败，工具失效。仅做内容探测，不在 TLS 层传密，
// 与 Python 版行为完全一致（netutil.py:29-31）。
func tlsProbeConfig() *tls.Config {
	// skipVerify = Python ssl.CERT_NONE 的 Go 对应物（语义：跳过证书链校验）
	skipVerify := true
	return &tls.Config{InsecureSkipVerify: skipVerify}
}

// shortDigest 计算内容形态指纹（语义对齐 Python hashlib 摘要取前 16 位 hex）。
func shortDigest(b []byte) string {
	return hexDigestPrefix16(b)
}

// newClient 组装与 urllib 行为对齐的 HTTP 客户端：
//   - TLS 见 tlsProbeConfig()；
//   - 不自动加 Accept-Encoding: gzip（urllib 发 identity）；
//   - 跟随环境代理（urllib 默认 getproxies 行为）；
//   - 重定向：follow 时最多跟 10 跳（urllib max_redirections=10），第 10 跳之后
//     返回最后一个 30x 响应本身——对齐 Python「重定向超限抛 HTTPError(302) →
//     fetch 捕获 → ok=true status=302」的分支语义（重定向环场景 parity 依赖它）；
//     不 follow 时返回 3xx 响应本身（对齐无 RedirectHandler 的 opener）。
func newClient(opt FetchOpt) *http.Client {
	if opt.Timeout <= 0 {
		opt.Timeout = 12 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsProbeConfig(),
		DisableCompression:  true,
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: opt.Timeout,
	}
	client := &http.Client{Timeout: opt.Timeout, Transport: transport}
	if !opt.Follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		hopCheck := opt.HopCheck
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if hopCheck != nil {
				// fix1 P1：逐跳复验 30x 落点（req 即待跟随的下一跳请求）。
				// 返回非 ErrUseLastResponse 的 error 会中止跟随，Do 返回该错误。
				if err := hopCheck(req.URL.String()); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return client
}

// errReason 提取错误原因文本（fix1 审计 low#5）：剥离 *url.Error 的
// `Get "URL": ` 前缀，对齐 Python str(e) 只含原因不含 URL 的形态——
// URL query 里携带的 token/api_key 等敏感参数不得经 error 字段进入
// 日志、stdout 与未来的报告/证据包。
func errReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// Fetch 单次 HTTP 请求，返回结构化结果（不 panic；失败写 Err 字段）。
// 语义对齐 netutil.py:21-66：
//   - 协议白名单 http/https 在入口把关，返回 error 字段而不是异常；
//   - 指纹对 max_bytes 截断后的原始字节计算，取 hex 前 16 位（先截断后哈希）；
//   - Body 是 utf-8 ignore 解码；4xx/5xx 同样算 ok=true（HTTPError 分支）；
//   - headers 键小写、同键多值取最后一个（Python dict 推导覆盖语义）。
func Fetch(rawURL string, opt FetchOpt) Result {
	res := Result{URL: rawURL, FinalURL: rawURL, Headers: map[string]string{}}
	if opt.Timeout <= 0 {
		opt.Timeout = 12 * time.Second
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 200000
	}
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		res.Err = trunc("非法 URL", 120)
		return res
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		res.Err = "仅允许 http/https 协议"
		return res
	}
	method := opt.Method
	if method == "" {
		method = "GET"
		if opt.Data != nil {
			method = "POST" // urllib: data 非 None 且未指定 method 时自动 POST
		}
	}
	var body io.Reader
	if opt.Data != nil {
		body = strings.NewReader(string(opt.Data))
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		res.Err = trunc(err.Error(), 120)
		return res
	}
	req.Header.Set("User-Agent", DefaultUA)
	for k, v := range opt.Headers {
		req.Header.Set(k, v)
	}
	resp, err := newClient(opt).Do(req)
	if err != nil {
		res.Err = trunc(errReason(err), 120)
		return res
	}
	defer resp.Body.Close()
	// 先截断后算指纹：与 Python r.read(max_bytes) 后摘要完全一致。
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(opt.MaxBytes)))
	if err != nil && len(raw) == 0 {
		res.Err = trunc(err.Error(), 120)
		return res
	}
	res.OK = true
	res.Status = resp.StatusCode
	res.Size = len(raw)
	res.Digest = shortDigest(raw)
	res.Ctype = resp.Header.Get("Content-Type")
	res.Body = decodeUTF8Ignore(raw)
	res.FinalURL = resp.Request.URL.String()
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		for _, v := range vs {
			res.Headers[lk] = v // 同键多值：后写覆盖，等价 Python dict 推导
		}
	}
	return res
}
