package netutil

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// probeRand 基线探针随机串：进程级生成一次，等价 Python secrets.token_hex(5)。
var probeRand string

func init() {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		probeRand = "0000000000"
	} else {
		probeRand = hex.EncodeToString(b) // 10 个十六进制字符
	}
}

// SameShape 两次响应"形态"是否一致（识别 catch-all），对齐 netutil.py:166-174：
// 状态码相等 且（指纹非空相等，或 长度相等非零且类型相等）。
func SameShape(a, b Result) bool {
	if a.Status != b.Status {
		return false
	}
	if a.Digest != "" && a.Digest == b.Digest {
		return true
	}
	return a.Size != 0 && a.Size == b.Size && a.Ctype == b.Ctype
}

// BaselineResult 对齐 Python baseline() 返回 dict 的键。
type BaselineResult struct {
	Kind     string `json:"kind"`
	Status   int    `json:"status"`
	Digest   string `json:"digest"`
	Size     int    `json:"size"`
	Ctype    string `json:"ctype"`
	FinalURL string `json:"final_url"`
	Samples  int    `json:"samples"`
}

// MarshalJSON 落盘形态对齐 Python（fix2 audit low#3②）：探针 <2 次成功时
// Python 只返回 {"kind":"unknown","samples":N} 两键（netutil.py:197），
// Go 零值结构体此前恒序列化 7 键。normal/soft404/… 分支仍全键输出。
func (b BaselineResult) MarshalJSON() ([]byte, error) {
	if b.Kind == "unknown" {
		return json.Marshal(struct {
			Kind    string `json:"kind"`
			Samples int    `json:"samples"`
		}{b.Kind, b.Samples})
	}
	type alias BaselineResult
	return json.Marshal(alias(b))
}

// Baseline 取两个随机不存在路径的响应判断 catch-all 行为，对齐 netutil.py:177-199：
// <2 次 ok → unknown；形态一致时按状态码分类 200→soft404、401/403→uniform403、
// 301/302→redirect，否则 normal。注意重定向环场景：Python 侧 urllib 重定向超限
// 抛 HTTPError(302) 被 fetch 捕获为 ok=true，两次探针指纹同为空串摘要，判为
// redirect——Go 侧 newClient 的 CheckRedirect 语义已对齐这一点。
func Baseline(baseURL string, timeout time.Duration, hop func(string) error) BaselineResult {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	base := strings.TrimRight(baseURL, "/")
	var oks []Result
	for i := 1; i <= 2; i++ {
		// fix3（audit high#1）：基线探针与主探测同受逐跳校验约束——30x 落点
		// 不设防时 status/size/digest/final_url 落进产物构成内网可达性 oracle
		r := Fetch(fmt.Sprintf("%s/_%s%d", base, probeRand, i),
			FetchOpt{Timeout: timeout, Follow: true, HopCheck: hop})
		if r.OK {
			oks = append(oks, r)
		}
	}
	if len(oks) < 2 {
		return BaselineResult{Kind: "unknown", Samples: len(oks)}
	}
	kind := "normal"
	if SameShape(oks[0], oks[1]) {
		switch oks[0].Status {
		case 200:
			kind = "soft404"
		case 401, 403:
			kind = "uniform403"
		case 301, 302:
			kind = "redirect"
		}
	}
	return BaselineResult{
		Kind: kind, Status: oks[0].Status, Digest: oks[0].Digest, Size: oks[0].Size,
		Ctype: oks[0].Ctype, FinalURL: oks[0].FinalURL, Samples: 2,
	}
}

// IsBaseline 该响应是否只是站点的 catch-all，对齐 netutil.py:202-209：
// redirect 类：final_url != url 即被统一重定向走，不算命中；
// 其余：与基线形态比对。
func IsBaseline(resp Result, base BaselineResult) bool {
	if base.Kind == "" || base.Kind == "normal" || base.Kind == "unknown" {
		return false
	}
	if base.Kind == "redirect" {
		return resp.FinalURL != resp.URL
	}
	return SameShape(resp, Result{Status: base.Status, Digest: base.Digest, Size: base.Size, Ctype: base.Ctype})
}

// Attempt 存活复验的单次请求摘要（JSON 键序对齐 Python netutil.py:227）。
// fix3（audit medium#3）：请求失败时 Python r.get() 为 null，Go 零值此前
// 序列化 0/""——ok 标记 + MarshalJSON 还原 null 语义。
type Attempt struct {
	Status int    `json:"-"`
	Size   int    `json:"-"`
	Digest string `json:"-"`
	ok     bool   `json:"-"`
}

func (a Attempt) MarshalJSON() ([]byte, error) {
	if !a.ok {
		return json.Marshal(struct {
			Status any `json:"status"`
			Size   any `json:"size"`
			Digest any `json:"digest"`
		}{})
	}
	return json.Marshal(struct {
		Status int    `json:"status"`
		Size   int    `json:"size"`
		Digest string `json:"digest"`
	}{a.Status, a.Size, a.Digest})
}

// LiveResult 对齐 Python verify_live() 返回 dict。
type LiveResult struct {
	Live     bool      `json:"live"`
	Attempts []Attempt `json:"attempts"`
	Note     string    `json:"note"`
}

// VerifyLive 存活复验，对齐 netutil.py:212-225：
// 连续 tries 次请求；特征消失/状态码不一致立即判死；全部 ok 后
// 「指纹全相等且非空 或 长度全相等」才算存活。
func VerifyLive(rawURL string, tries int, timeout time.Duration, expectBody string, hop func(string) error) LiveResult {
	if tries < 1 {
		tries = 1
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	var attempts []Attempt
	for i := 0; i < tries; i++ {
		r := Fetch(rawURL, FetchOpt{Timeout: timeout, Follow: true, HopCheck: hop})
		attempts = append(attempts, Attempt{Status: r.Status, Size: r.Size, Digest: r.Digest, ok: r.OK})
		if expectBody != "" && !strings.Contains(strings.ToLower(r.Body), strings.ToLower(expectBody)) {
			return LiveResult{Live: false, Attempts: attempts, Note: "复验时特征消失"}
		}
		if !r.OK || r.Status != attempts[0].Status {
			return LiveResult{Live: false, Attempts: attempts, Note: "复验状态码不一致"}
		}
	}
	allSHA := attempts[0].Digest != ""
	allSize := true
	for _, a := range attempts[1:] {
		if a.Digest == "" || a.Digest != attempts[0].Digest {
			allSHA = false
		}
		if a.Size != attempts[0].Size {
			allSize = false
		}
	}
	consistent := allSHA || allSize
	note := "两次一致"
	if !consistent {
		note = "两次响应不一致（疑似瞬时/WAF 抖动）"
	}
	return LiveResult{Live: consistent, Attempts: attempts, Note: note}
}
