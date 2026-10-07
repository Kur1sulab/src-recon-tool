package parity

import (
	"encoding/json"
	neturl "net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"
	"github.com/Kur1sulab/src-recon-tool/engine-go/netutil"
	"github.com/Kur1sulab/src-recon-tool/engine-go/subdomain"
	"github.com/Kur1sulab/src-recon-tool/engine-go/toolrun"
)

// 本文件是 Python↔Go parity 断言矩阵。两引擎打同一个 mockweb 靶站；
// python 缺席时 RequiresPython 会 t.Skip（纯 Go 测试不受影响）。

const pyNetutilFetch = `
import json, sys
sys.path.insert(0, 'src')
from modules import netutil
print(json.dumps(netutil.fetch(sys.argv[1], timeout=int(sys.argv[2])), ensure_ascii=False))
`

// ① Baseline：kind + status 五场景（Python 实测真值钉死，含重定向环）。
func TestParityBaseline(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()
	cases := map[string]string{
		"soft404":       "soft404",
		"waf":           "uniform403",
		"loginredirect": "redirect",
		"empty":         "normal",
		"api404":        "soft404",
	}
	for sc, wantKind := range cases {
		base := srv.URL + "/" + sc
		py := PyJSON(t, `
import json, sys
sys.path.insert(0, 'src')
from modules import netutil
print(json.dumps(netutil.baseline(sys.argv[1], timeout=5), ensure_ascii=False))
`, base)
		goB := netutil.Baseline(base, 5*time.Second, nil)
		if py["kind"] != wantKind || goB.Kind != wantKind {
			t.Errorf("[%s] kind: py=%v go=%s, want %s", sc, py["kind"], goB.Kind, wantKind)
			continue
		}
		pyStatus := int(py["status"].(float64))
		if pyStatus != goB.Status {
			t.Errorf("[%s] status: py=%d go=%d", sc, pyStatus, goB.Status)
		}
		if py["digest"] != goB.Digest {
			t.Errorf("[%s] digest: py=%v go=%s", sc, py["digest"], goB.Digest)
		}
		if int(py["size"].(float64)) != goB.Size {
			t.Errorf("[%s] size: py=%v go=%d", sc, py["size"], goB.Size)
		}
		if py["ctype"] != goB.Ctype {
			t.Errorf("[%s] ctype: py=%v go=%s", sc, py["ctype"], goB.Ctype)
		}
		// final_url：非 redirect 场景含进程级随机探针路径（Python 每次 import 重新
		// token_hex(5)、Go 进程级 crypto/rand）——两引擎各随机各的，只能断言"停在
		// 探针 1 路径"；redirect 场景两引擎都停在 /loginredirect/login，可全等比较。
		if wantKind == "redirect" {
			if py["final_url"] != goB.FinalURL {
				t.Errorf("[%s] redirect final_url: py=%v go=%s", sc, py["final_url"], goB.FinalURL)
			}
		} else {
			if !strings.HasSuffix(py["final_url"].(string), "1") || !strings.HasSuffix(goB.FinalURL, "1") {
				t.Errorf("[%s] final_url 应为探针 1 路径: py=%v go=%s", sc, py["final_url"], goB.FinalURL)
			}
		}
	}
}

// ② Fetch 结构化字段 parity（ok/status/size/digest/ctype/body/final_url）。
func TestParityFetch(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()
	for _, path := range []string{"/real/swagger-ui.html", "/real/actuator/heapdump",
		"/waf/abc", "/api404/x", "/empty/y", "/loginredirect/z"} {
		u := srv.URL + path
		py := PyJSON(t, pyNetutilFetch, u, "5")
		goR := netutil.Fetch(u, netutil.FetchOpt{Timeout: 5 * time.Second, Follow: true})
		gm := ToMap(t, goR)
		for _, k := range []string{"ok", "status", "size", "digest", "ctype", "body", "final_url"} {
			if !reflect.DeepEqual(py[k], gm[k]) {
				t.Errorf("[%s] %s: py=%v go=%v", path, k, py[k], gm[k])
			}
		}
	}
}

// ③ Fingerprint 命中序列 parity（names+types+顺序）。
func TestParityFingerprint(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()
	pyCode := `
import json, sys
sys.path.insert(0, 'src')
from modules.fingerprint import run_fingerprint
run_fingerprint(sys.argv[1], sys.argv[2])
hits = json.load(open(sys.argv[2] + '/fingerprint.json', encoding='utf-8'))
print(json.dumps(hits, ensure_ascii=False))
`
	for _, path := range []string{"/real/swagger-ui.html", "/fppage/index", "/soft404/x"} {
		u := srv.URL + path
		pyHits := PyJSONLastLine(t, pyCode, u, t.TempDir())
		goOut := t.TempDir()
		fingerprint.RunFingerprint(u, goOut)
		raw, err := os.ReadFile(filepath.Join(goOut, "fingerprint.json"))
		if err != nil {
			t.Fatal(err)
		}
		var goHits []map[string]any
		if err := json.Unmarshal(raw, &goHits); err != nil {
			t.Fatal(err)
		}
		if len(pyHits) != len(goHits) {
			t.Errorf("[%s] 命中数: py=%d go=%d", path, len(pyHits), len(goHits))
			continue
		}
		for i := range pyHits {
			pm := pyHits[i].(map[string]any)
			if pm["name"] != goHits[i]["name"] || pm["type"] != goHits[i]["type"] {
				t.Errorf("[%s] 第 %d 项: py=%v go=%v", path, i, pyHits[i], goHits[i])
			}
		}
	}
}

// ④ HTTPProbe 字段 parity（127.0.0.1 字面量 + 同一靶站端口）。
func TestParityHTTPProbe(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()
	u, err := neturl.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	py := PyJSON(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.subdomain import http_probe
print(json.dumps(http_probe("127.0.0.1", timeout=5, port=int(sys.argv[1])), ensure_ascii=False))
`, strconv.Itoa(port))
	goP := subdomain.HTTPProbe("127.0.0.1", 5*time.Second, port)
	gm := ToMap(t, goP)
	for _, k := range []string{"scheme", "status", "ctype", "title", "final_url"} {
		if !reflect.DeepEqual(py[k], gm[k]) {
			t.Errorf("probe %s: py=%v go=%v", k, py[k], gm[k])
		}
	}
	if py["server"] != "" || goP.Server != "" {
		t.Errorf("server 头两侧都应为空（Go 靶站无 Server 头）: py=%v go=%q", py["server"], goP.Server)
	}
}

// ⑤ VerifySubs rows parity（do_http=false；锚点 127.0.0.1 字面量）。
func TestParityVerifySubs(t *testing.T) {
	RequiresPython(t)
	out := RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.subdomain import verify_subs
print(json.dumps(verify_subs(["127.0.0.1"], workers=2, do_http=False), ensure_ascii=False))
`)
	var pyRows []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &pyRows); err != nil {
		t.Fatalf("python rows 解析失败: %v\n%s", err, out)
	}
	goRows := subdomain.VerifySubs([]string{"127.0.0.1"}, 2, false, 120)
	if len(pyRows) != len(goRows) {
		t.Fatalf("行数: py=%d go=%d", len(pyRows), len(goRows))
	}
	for i := range pyRows {
		pr, gr := pyRows[i], goRows[i]
		if pr["host"] != gr.Host {
			t.Errorf("host: py=%v go=%s", pr["host"], gr.Host)
		}
		pyIPs, _ := pr["ips"].([]any)
		if len(pyIPs) != len(gr.IPs) {
			t.Errorf("ips: py=%v go=%v", pr["ips"], gr.IPs)
		} else {
			for j := range pyIPs {
				if pyIPs[j].(string) != gr.IPs[j] {
					t.Errorf("ips[%d]: py=%v go=%v", j, pyIPs[j], gr.IPs[j])
				}
			}
		}
		if pr["alive"] != gr.Alive {
			t.Errorf("alive: py=%v go=%v", pr["alive"], gr.Alive)
		}
		pyHTTP, _ := pr["http"].(map[string]any)
		if len(pyHTTP) != 0 || gr.HTTP != (subdomain.ProbeResult{}) {
			t.Errorf("do_http=false 时 http 应为空: py=%v go=%v", pyHTTP, gr.HTTP)
		}
	}
}

// ⑥ OneForAll 适配器 parity：同一 fixture（含尾逗号/重复/前导点/大写/脏行），
// 两引擎解析出同一子域列表。
func TestParityOneForAll(t *testing.T) {
	RequiresPython(t)
	fixture, err := os.ReadFile(filepath.Join(RepoRoot(), "engine-go", "testdata", "oneforall_fake.py.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pyHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(pyHome, "oneforall.py"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ONEFORALL_HOME", pyHome) // Python 侧 _from_oneforall 读环境变量定位
	domain := "fixture.example"
	pyOut := RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.subdomain import _from_oneforall
print(json.dumps(_from_oneforall(sys.argv[1], sys.argv[2]), ensure_ascii=False))
`, domain, t.TempDir())
	// fixture 自身会打一行日志，JSON 在最后一行
	pyLines := strings.Split(strings.TrimSpace(pyOut), "\n")
	var pySubs []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyLines[len(pyLines)-1])), &pySubs); err != nil {
		t.Fatalf("python 子域解析失败: %v\n%s", err, pyOut)
	}
	goHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(goHome, "oneforall.py"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	goSubs := toolrun.RunOneForAll(goHome, domain, t.TempDir(), 60*time.Second)
	if !reflect.DeepEqual(pySubs, goSubs) {
		t.Fatalf("OneForAll 适配器 parity:\n  py=%v\n  go=%v", pySubs, goSubs)
	}
	if len(goSubs) != 4 || goSubs[0] != "MAIL.fixture.example" {
		t.Fatalf("fixture 期望 4 项（含大写去重排序），got %v", goSubs)
	}
}
