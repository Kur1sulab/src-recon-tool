package mockweb

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/parity"
)

// TestScenarios 纯 Go 结构测试：各场景路由/状态码/内容片段（不依赖 python）。
func TestScenarios(t *testing.T) {
	srv := New()
	defer srv.Close()
	// 不跟随重定向的客户端（默认 client 会跟到重定向环耗尽报错）
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	get := func(path string) (*http.Response, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	if resp, body := get("/soft404/anything"); resp.StatusCode != 200 || !strings.Contains(body, "My App") {
		t.Errorf("soft404: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get("/waf/x"); resp.StatusCode != 403 {
		t.Errorf("waf: %d", resp.StatusCode)
	}
	{
		resp, err := noRedirect.Get(srv.URL + "/loginredirect/x")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 302 || resp.Header.Get("Location") != "/loginredirect/login" {
			t.Errorf("loginredirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if resp, _ := get("/empty/x"); resp.StatusCode != 404 {
		t.Errorf("empty: %d", resp.StatusCode)
	}
	if resp, body := get("/api404/x"); resp.StatusCode != 200 || !strings.Contains(body, `"code":200`) {
		t.Errorf("api404: %d %q", resp.StatusCode, body)
	}
	for _, p := range TruePositives {
		if resp, _ := get("/real" + p); resp.StatusCode != 200 {
			t.Errorf("real%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := get("/real/not-exist"); resp.StatusCode != 404 {
		t.Errorf("real 未列路径应 404: %d", resp.StatusCode)
	}
	if resp, _ := get("/"); resp.StatusCode != 404 {
		t.Errorf("未知场景应 404: %d", resp.StatusCode)
	}
	// fppage 受控显式头
	req, _ := http.NewRequest("GET", srv.URL+"/fppage/x", nil)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("Server") != "nginx" || resp2.Header.Get("X-Powered-By") != "PHP/7.4" {
		t.Errorf("fppage 受控头缺失: %v", resp2.Header)
	}
}

// TestRealConstantsMatchPythonMock 静态漂移守卫：Go mock 的 SPA/REAL 常量与
// tests/mock_server.py 内嵌常量逐字节比对（python 缺席时 skip，铁律）。
func TestRealConstantsMatchPythonMock(t *testing.T) {
	code := `
import base64, json, sys
sys.path.insert(0, '.')
from tests.mock_server import REAL, SPA_SHELL
print(json.dumps({
    "spa": base64.b64encode(SPA_SHELL.encode("utf-8")).decode(),
    "real": {k: [v[0], base64.b64encode(v[1].encode("utf-8")).decode()] for k, v in REAL.items()},
}, sort_keys=True))
`
	out := parity.RunPy(t, code)
	var py struct {
		Spa  string              `json:"spa"`
		Real map[string][]string `json:"real"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &py); err != nil {
		t.Fatalf("python 常量导出解析失败: %v\n%s", err, out)
	}
	if got, err := base64.StdEncoding.DecodeString(py.Spa); err != nil || string(got) != SPAShell {
		t.Errorf("SPA_SHELL 与 Python 侧漂移（len go=%d py=%d）", len(SPAShell), len(got))
	}
	if len(py.Real) != len(Real) {
		t.Fatalf("REAL 键数不一致: go=%d py=%d", len(Real), len(py.Real))
	}
	for k, pv := range py.Real {
		e, ok := Real[k]
		if !ok {
			t.Errorf("Go 侧缺 REAL 键 %q", k)
			continue
		}
		if e.Ctype != pv[0] {
			t.Errorf("REAL[%s] ctype: go=%q py=%q", k, e.Ctype, pv[0])
		}
		want, err := base64.StdEncoding.DecodeString(pv[1])
		if err != nil || string(want) != e.Body {
			t.Errorf("REAL[%s] body 与 Python 逐字节漂移（len go=%d py=%d）", k, len(e.Body), len(want))
		}
	}
}
