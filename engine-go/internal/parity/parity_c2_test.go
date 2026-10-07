package parity

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/apiunauth"
	"github.com/Kur1sulab/src-recon-tool/engine-go/asset"
	"github.com/Kur1sulab/src-recon-tool/engine-go/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"
	"github.com/Kur1sulab/src-recon-tool/engine-go/paths"
	"github.com/Kur1sulab/src-recon-tool/engine-go/poc"
	"github.com/Kur1sulab/src-recon-tool/engine-go/report"
	"github.com/Kur1sulab/src-recon-tool/engine-go/reverseip"
)

// ── ① parse_icp parity（含限频假 200）──
func TestParityParseICP(t *testing.T) {
	RequiresPython(t)
	cases := []string{
		`{"code":200,"td":"1-1","type":"企业","icp":"粤B2-20090059-5","unit":"深圳市腾讯计算机系统有限公司","domain":"qq.com","time":"2026-01-15"}`,
		`{"code":400,"msg":"查询失败或没有备案。"}`,
		`{"code":200,"icp":"查询失败","unit":"查询失败","domain":"查询失败","time":"查询失败"}`,
		`<html>502</html>`,
	}
	for _, in := range cases {
		py := PyJSON(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.icp import parse_icp
print(json.dumps(parse_icp(sys.argv[1]), ensure_ascii=False))
`, in)
		goM := icp.ParseICP(in)
		gm := ToMap(t, goM)
		for _, k := range []string{"filed", "msg", "icp", "unit"} {
			pv, pok := py[k]
			gv, gok := gm[k]
			if pok != gok || (pok && !reflect.DeepEqual(pv, gv)) {
				t.Errorf("parse_icp(%q) [%s]: py=%v go=%v", truncS(in, 40), k, py[k], gm[k])
			}
		}
	}
}

// ── ② parse_hackertarget 黄金样例 parity ──
func TestParityParseHackerTarget(t *testing.T) {
	RequiresPython(t)
	raw := "xycovo.com\nwww.xycovo.com\n0.0.d.5.9.6.0.7.4.0.1.0.0.2.ip6.arpa\nnot a domain\napi.example.com.\n\nXYCOVO.COM\n"
	pyOut := RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.reverse_ip import parse_hackertarget
print(json.dumps(parse_hackertarget(sys.argv[1])))
`, raw)
	var pyList []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyOut)), &pyList); err != nil {
		t.Fatalf("python 输出解析失败: %v\n%s", err, pyOut)
	}
	goList := reverseip.ParseHackerTarget(raw)
	if !reflect.DeepEqual(pyList, goList) {
		t.Fatalf("parse_hackertarget:\n  py=%v\n  go=%v", pyList, goList)
	}
}

// ── ③ classify 六例 parity（黄金用例逐条）──
func TestParityClassify(t *testing.T) {
	RequiresPython(t)
	type c struct {
		path, body, ctype string
		status, size      int
		expect            []string
	}
	cases := []c{
		{"/v3/api-docs", `{"openapi":"3.0.1","paths":{}}`, "application/json", 200, 30, []string{`"openapi"`, `"paths"`}},
		{"/v3/api-docs", "<html><body>首页</body></html>", "text/html", 200, 30, []string{`"openapi"`, `"paths"`}},
		{"/actuator", "", "", 404, 0, []string{`"_links"`}},
		{"/actuator/heapdump", "JAVA PROFILE 1.0.8\x00\x00", "application/octet-stream", 200, 4114, []string{"java profile"}},
		{"/actuator/heapdump", strings.Repeat("x", 5000), "application/octet-stream", 200, 5000, []string{"java profile"}},
		{"/api/v1/users", `{"data":{"username":"a","email":"a@b.c"}}`, "application/json", 200, 60, []string{`"username"`, `"email"`}},
	}
	for _, tc := range cases {
		expectJSON, _ := json.Marshal(tc.expect)
		pyOut := RunPyStdin(t, tc.body, `
import json, sys
sys.path.insert(0, 'src')
from modules.api_unauth import classify
print(json.dumps(classify(sys.argv[1], int(sys.argv[2]), sys.stdin.read(), sys.argv[3], int(sys.argv[4]), json.loads(sys.argv[5])), ensure_ascii=False))
`, tc.path, itoa(tc.status), tc.ctype, itoa(tc.size), string(expectJSON))
		pyLines := strings.Split(strings.TrimSpace(pyOut), "\n")
		var py map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(pyLines[len(pyLines)-1])), &py); err != nil {
			t.Fatalf("python 输出解析失败: %v\n%s", err, pyOut)
		}
		goV := apiunauth.Classify(tc.path, tc.status, tc.body, tc.ctype, tc.size, tc.expect)
		if py["hit"] != goV.Hit {
			t.Errorf("classify(%s): py=%v go=%v", tc.path, py["hit"], goV.Hit)
			continue
		}
		if goV.Hit {
			if py["marker"] != goV.Marker || py["evidence"] != goV.Evidence {
				t.Errorf("classify(%s): marker/evidence py=%v/%v go=%v/%v",
					tc.path, py["marker"], py["evidence"], goV.Marker, goV.Evidence)
			}
		}
	}
}

// ── ④ poc _match 四例 parity ──
func TestParityPocMatch(t *testing.T) {
	RequiresPython(t)
	type mc struct {
		matchers  string // JSON
		status    int
		body      string
		condition string
	}
	cases := []mc{
		{`[{"type": "status", "status": [200]}]`, 200, "", "or"},
		{`[{"type": "status", "status": [200]}]`, 404, "", "or"},
		{`[{"type": "contains", "words": ["admin"]}]`, 200, "<title>admin</title>", "or"},
		{`[{"type": "status", "status": [200]}, {"type": "contains", "words": ["login"]}]`, 200, "hello", "and"},
	}
	for _, tc := range cases {
		pyOut := RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.poc_engine import _match
print(json.dumps(_match(json.loads(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4])))
`, tc.matchers, itoa(tc.status), tc.body, tc.condition)
		goB := poc.Match(mustMatchers(t, tc.matchers), tc.status, tc.body, tc.condition)
		if strings.TrimSpace(pyOut) != boolPy(goB) {
			t.Errorf("_match(%s): py=%s go=%v", tc.matchers, pyOut, goB)
		}
	}
}

// ── ⑤ render_md parity：合成 bundle → 逐行 diff（跳过生成时间行）──
func TestParityRenderMD(t *testing.T) {
	RequiresPython(t)
	bundle := map[string]any{
		"target":          "example.com",
		"generated_at":    "2026-10-02T00:00:00+08:00",
		"reverse_domains": []string{"example.com"},
		"subdomains":      []string{"a.example.com", "b.example.com"},
		"subdomains_live": []map[string]any{
			{"host": "a.example.com", "ips": []string{"1.2.3.4"}, "alive": true,
				"http": map[string]any{"scheme": "https", "status": 200, "title": "T"}},
			{"host": "b.example.com", "ips": []any{}, "alive": false, "http": map[string]any{}},
		},
		"icp": map[string]any{
			"example.com": map[string]any{"domain": "example.com", "filed": true,
				"icp": "京ICP备00000000号-1", "unit": "示例科技有限公司", "type": "企业", "time": "2026-01-01"},
		},
		"fingerprint": []map[string]any{{"name": "Swagger UI", "type": "api"}},
		"paths": map[string]any{
			"base": "https://example.com", "baseline": map[string]any{"kind": "soft404"},
			"alive": []map[string]any{{"path": "/.env", "status": 200, "size": 63, "verified": true}},
			"notes": []any{},
		},
		"api": map[string]any{
			"base": "https://example.com", "probed": 27, "live_hits": 1, "soft404_filtered": 3,
			"hits": []map[string]any{{"path": "/actuator/env", "name": "Actuator env（含配置/口令）",
				"risk": "高", "live": true, "evidence_dir": "actuator_env",
				"evidence": `body 含 "propertysources"`}},
		},
		"jsintel": map[string]any{
			"base": "https://example.com", "page_status": 200,
			"scripts":        map[string]any{"external": 3, "inline": 1, "downloaded": 3, "failed": 0},
			"endpoints":      []string{"/api/v1/users"},
			"endpoints_full": []string{"https://example.com/api/v1/users"},
			"sensitive":      map[string]any{"secret": "masked"},
			"domains": map[string]any{"subdomains": []string{"api.example.com"},
				"thirdparty": []string{"cdn.third.cn"}, "internal_ips": []string{"10.0.0.5"}},
		},
		"ports": map[string]any{
			"target": "example.com", "ip": "1.2.3.4", "scanned": 100, "open_count": 2,
			"open": []map[string]any{
				{"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.0"},
				{"port": 443, "service": "", "banner": ""},
			},
		},
		"llm_summary": "",
	}
	bundle["jsintel"].(map[string]any)["sensitive"] = []map[string]any{
		{"file": "/js/app.js", "line": 5, "key": "password", "value": "Sup3****", "snippet": "var cfg2={password:'Sup3****'"},
	}
	stdin, _ := json.Marshal(bundle)
	pyMD := RunPyStdin(t, string(stdin), `
import json, sys
sys.path.insert(0, 'src')
from modules.report import render_md
print(render_md(json.load(sys.stdin)))
`)
	goMD := report.RenderMD(bundle)
	// python print 在 Windows 输出 CRLF——diff 前 strip \r（铁律 parity 纪律）
	pyMD = StripCR(pyMD)
	pyLines := strings.Split(strings.TrimRight(pyMD, "\n"), "\n")
	goLines := strings.Split(goMD, "\n")
	if len(pyLines) != len(goLines) {
		t.Fatalf("行数不一致: py=%d go=%d\n--- py ---\n%s\n--- go ---\n%s", len(pyLines), len(goLines), pyMD, goMD)
	}
	for i := range pyLines {
		if strings.HasPrefix(pyLines[i], "- 生成时间：") || strings.HasPrefix(goLines[i], "- 生成时间：") {
			continue // 时间行允许漂移（clock 注入口径）
		}
		if pyLines[i] != goLines[i] {
			t.Errorf("第 %d 行不一致:\n  py=%q\n  go=%q", i+1, pyLines[i], goLines[i])
		}
	}
}

// ── ⑥ paths + api 全链路 parity（两引擎打同一个 mockweb 靶站）──
func TestParityPathsAndAPIFullChain(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()

	// 误报陷阱：五场景两引擎都零命中
	for _, sc := range []string{"soft404", "api404", "waf", "loginredirect", "empty"} {
		scenario := srv.URL + "/" + sc
		pyAPI := lastJSONLine(RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.api_unauth import run_api
hits = run_api(sys.argv[1], sys.argv[2])
print(json.dumps([h["path"] for h in hits]))
`, scenario, t.TempDir()))
		pyPaths := lastJSONLine(RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.paths import run_paths
alive = run_paths(sys.argv[1], sys.argv[2])
print(json.dumps([a["path"] for a in alive]))
`, scenario, t.TempDir()))
		goAPIHits, err := apiunauth.RunAPI(scenario, t.TempDir(), false)
		if err != nil {
			t.Fatal(err)
		}
		goPathsAlive, err := paths.RunPaths(scenario, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(pyAPI) != "[]" || len(goAPIHits) != 0 {
			t.Errorf("[%s] api 命中: py=%s go=%d", sc, pyAPI, len(goAPIHits))
		}
		if strings.TrimSpace(pyPaths) != "[]" || len(goPathsAlive) != 0 {
			t.Errorf("[%s] paths 存活: py=%s go=%d", sc, pyPaths, len(goPathsAlive))
		}
	}

	// 真阳性：real 场景必含五端点且全 live；paths 必含三路径全 verified
	real := srv.URL + "/real"
	pyAPI := lastJSONLine(RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.api_unauth import run_api
hits = run_api(sys.argv[1], sys.argv[2])
print(json.dumps([[h["path"], bool(h.get("live"))] for h in hits]))
`, real, t.TempDir()))
	var pyHits [][2]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyAPI)), &pyHits); err != nil {
		t.Fatal(err)
	}
	pyGot := map[string]bool{}
	for _, h := range pyHits {
		p, _ := h[0].(string)
		live, _ := h[1].(bool)
		pyGot[p] = live
	}
	goHits, err := apiunauth.RunAPI(real, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	goGot := map[string]bool{}
	for _, h := range goHits {
		live, _ := h["live"].(bool)
		goGot[h["path"].(string)] = live
	}
	for _, need := range []string{"/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/env", "/actuator/heapdump"} {
		if !pyGot[need] || !goGot[need] {
			t.Errorf("漏报 %s: py=%v go=%v", need, pyGot[need], goGot[need])
		}
	}
	pyPaths := lastJSONLine(RunPy(t, `
import json, sys
sys.path.insert(0, 'src')
from modules.paths import run_paths
alive = run_paths(sys.argv[1], sys.argv[2])
print(json.dumps([[a["path"], bool(a.get("verified"))] for a in alive]))
`, real, t.TempDir()))
	var pyAlive [][2]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyPaths)), &pyAlive); err != nil {
		t.Fatal(err)
	}
	pyP := map[string]bool{}
	for _, a := range pyAlive {
		p, _ := a[0].(string)
		v, _ := a[1].(bool)
		pyP[p] = v
	}
	goAlive, err := paths.RunPaths(real, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	goP := map[string]bool{}
	for _, a := range goAlive {
		goP[a.Path] = a.Verified != nil && *a.Verified
	}
	for _, need := range []string{"/.env", "/robots.txt", "/actuator"} {
		if !pyP[need] || !goP[need] {
			t.Errorf("paths 漏报 %s: py=%v go=%v", need, pyP[need], goP[need])
		}
	}
}

// ── ⑦ FOFA/Hunter 解析层 parity（python 内联重放推导式 vs Go 纯函数）──
func TestParityAssetParsers(t *testing.T) {
	RequiresPython(t)
	fofaJSON := `{"error":false,"results":[["a.com:443","1.2.3.4",443,"https"],[null,"5.6.7.8",80,"http"]]}`
	pyFofa := RunPy(t, `
import json, sys
data = json.loads(sys.argv[1])
print(json.dumps([f"{r[0]}|{r[1]}|{r[2]}|{r[3]}" for r in data.get("results", [])]))
`, fofaJSON)
	var raw struct {
		Results [][]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(fofaJSON), &raw); err != nil {
		t.Fatal(err)
	}
	goFofa := assetParseFofa(raw.Results)
	var pyFofaList []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyFofa)), &pyFofaList); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pyFofaList, goFofa) {
		t.Errorf("FOFA 解析:\n  py=%v\n  go=%v", pyFofaList, goFofa)
	}

	hunterJSON := `[{"domain":"a.com","ip":"1.2.3.4","port":443,"protocol":"https"},{"domain":"b.com"}]`
	pyHunter := RunPy(t, `
import json, sys
arr = json.loads(sys.argv[1])
print(json.dumps([f"{a.get('domain','')}|{a.get('ip','')}|{a.get('port','')}|{a.get('protocol','')}" for a in arr]))
`, hunterJSON)
	var arr []map[string]any
	if err := json.Unmarshal([]byte(hunterJSON), &arr); err != nil {
		t.Fatal(err)
	}
	goHunter := assetParseHunter(arr)
	var pyHunterList []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(pyHunter)), &pyHunterList); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pyHunterList, goHunter) {
		t.Errorf("Hunter 解析:\n  py=%v\n  go=%v", pyHunterList, goHunter)
	}
}

// ── ⑧ pack_evidence parity：两侧各打包，比较 arcname 集合与成员内容 ──
func TestParityPackEvidence(t *testing.T) {
	RequiresPython(t)
	// Python 侧合成证据目录并打包
	pyOut := t.TempDir()
	pyEv := filepath.Join(pyOut, "evidence", "example.com", "actuator_env")
	RunPy(t, `
import json, os, sys
out, ev = sys.argv[1], sys.argv[2]
os.makedirs(ev, exist_ok=True)
open(os.path.join(ev, "meta.json"), "w", encoding="utf-8").write('{"url": "u", "live": true}')
open(os.path.join(ev, "response.snippet.txt"), "w", encoding="utf-8").write("BODY")
open(os.path.join(ev, "repro.md"), "w", encoding="utf-8").write("curl -sk -i")
sys.path.insert(0, 'src')
from modules.report import pack_evidence
print(pack_evidence(out, "example.com"))
`, pyOut, pyEv)
	goOut := t.TempDir()
	goEv := filepath.Join(goOut, "evidence", "example.com", "actuator_env")
	if err := os.MkdirAll(goEv, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"meta.json": `{"url": "u", "live": true}`, "response.snippet.txt": "BODY", "repro.md": "curl -sk -i",
	} {
		if err := os.WriteFile(filepath.Join(goEv, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goZip := report.PackEvidence(goOut, "example.com")
	if goZip == "" {
		t.Fatal("Go 侧打包失败")
	}
	// 比较两侧 zip 的 arcname 集合与成员内容
	pyZips, _ := filepath.Glob(filepath.Join(pyOut, "evidence-*.zip"))
	if len(pyZips) != 1 {
		t.Fatalf("python 侧 zip = %v", pyZips)
	}
	pyNames, pyContent := readZip(t, pyZips[0])
	goNames, goContent := readZip(t, goZip)
	if !reflect.DeepEqual(pyNames, goNames) {
		t.Errorf("arcname 集合:\n  py=%v\n  go=%v", pyNames, goNames)
	}
	for n, c := range pyContent {
		if goContent[n] != c {
			t.Errorf("成员 %s 内容不一致", n)
		}
	}
}

// ── helpers ──

// lastJSONLine 取 python 混合输出（模块日志行 + 末尾 JSON 行）的最后一行。
func lastJSONLine(s string) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(ls) - 1; i >= 0; i-- {
		l := strings.TrimSpace(ls[i])
		if strings.HasPrefix(l, "[") || strings.HasPrefix(l, "{") {
			return l
		}
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }

// assetParseFofa / assetParseHunter：asset 包解析纯函数的别名（避免 import 循环顾虑）。
func assetParseFofa(results [][]any) []string { return asset.ParseFofaResults(results) }

func assetParseHunter(arr []map[string]any) []string { return asset.ParseHunterArr(arr) }

func boolPy(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func mustMatchers(t *testing.T, js string) []poc.Matcher {
	t.Helper()
	var ms []poc.Matcher
	if err := json.Unmarshal([]byte(js), &ms); err != nil {
		t.Fatal(err)
	}
	return ms
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func truncS(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func readZip(t *testing.T, path string) ([]string, map[string]string) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	content := map[string]string{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, _ := f.Open()
		b := make([]byte, 0, 256)
		buf := make([]byte, 512)
		for {
			n, rerr := rc.Read(buf)
			b = append(b, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		rc.Close()
		content[f.Name] = string(b)
	}
	return names, content
}
