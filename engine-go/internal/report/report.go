// Package report：资产档案 + 证据包，移植 src/modules/report.py。
// 纪律：只写实测结果、缺什么少什么不编造；report.md 不内联敏感值；幂等覆盖。
package report

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/netutil"
)

// Now 可注入时钟（测试固定 generated_at；默认本地时区 ISO 秒级，对齐
// datetime.now().astimezone().isoformat(timespec="seconds")）。
var Now = func() string {
	return time.Now().Format("2006-01-02T15:04:05Z07:00")
}

// ZipStamp 证据包文件名时间戳（可注入，测试固定）。
// fix2 P2：秒级戳 + os.Create 截断在「同秒并发 report 打同一 out/」时互相
// 覆盖（对抗实测 4 进程同秒只活 1 个 zip）——加纳秒、进程内原子序数与 PID
// 保证唯一（Windows 时钟粒度下纳秒可能同 tick 重复，序数兜底）；
// Python pack_evidence 同步该形态（parity：两引擎文件名同构）。
var (
	zipStampSeq atomic.Uint64
)

var ZipStamp = func() string {
	return time.Now().Format("20060102-150405.000000000") +
		fmt.Sprintf("-%04d-%d", zipStampSeq.Add(1), os.Getpid())
}

func readJSON(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func readJSONList(path string) []any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var l []any
	if err := json.Unmarshal(b, &l); err != nil {
		return nil
	}
	return l
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Collect 把各模块产出读进 Bundle（map，11 键对齐 report.py:39-64；
// 缺文件→零值不编造；icp_*.json glob 聚合按 domain 键）。
func Collect(out, target string) map[string]any {
	bundle := map[string]any{
		"target":          target,
		"generated_at":    Now(),
		"reverse_domains": readLines(filepath.Join(out, "reverse_domains.txt")),
		"subdomains":      readLines(filepath.Join(out, "subdomains.txt")),
		"subdomains_live": readJSONList(filepath.Join(out, "subdomains_live.json")),
		"icp":             map[string]any{},
		"fingerprint":     readJSONList(filepath.Join(out, "fingerprint.json")),
		"paths":           orMap(readJSON(filepath.Join(out, "paths.json"))),
		"api":             orMap(readJSON(filepath.Join(out, "api_unauth.json"))),
		"jsintel":         orMap(readJSON(filepath.Join(out, "jsintel.json"))),
		"ports":           orMap(readJSON(filepath.Join(out, "ports.json"))),
		"assets":          readLines(filepath.Join(out, "assets.txt")),
		"llm_summary":     "",
	}
	pattern := filepath.Join(out, "icp_*.json")
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	icp := bundle["icp"].(map[string]any)
	for _, p := range matches {
		d := readJSON(p)
		if d != nil && d["domain"] != nil {
			icp[fmt.Sprintf("%v", d["domain"])] = d
		}
	}
	if llm, err := os.ReadFile(filepath.Join(out, "llm_summary.md")); err == nil {
		s := []rune(string(llm))
		if len(s) > 4000 {
			s = s[:4000]
		}
		bundle["llm_summary"] = string(s)
	}
	return bundle
}

func orMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// RenderMD 渲染资产档案，逐行对齐 report.py:67-189。
func RenderMD(b map[string]any) string {
	L := []string{}
	a := func(s string) { L = append(L, s) }
	target := strV(b["target"])
	a(fmt.Sprintf("# 目标资产档案 · %s\n", target))
	a(fmt.Sprintf("- 生成时间：%s", strV(b["generated_at"])))
	a(fmt.Sprintf("- 输出目录：`out/%s/`", target))
	a("- 声明：本档案仅记录**工具实测**结果；未验证项已标注，不含推断性结论\n")

	rev := strList(b["reverse_domains"])
	icp, _ := b["icp"].(map[string]any)
	if len(rev) > 0 {
		a("## 1. 归属线索\n")
		a("| 项 | 结果 |")
		a("|---|---|")
		top := rev
		if len(top) > 10 {
			top = top[:10]
		}
		a(fmt.Sprintf("| IP 反查域名 | %s |", strings.Join(top, ", ")))
		// fix2 audit low#4：Go map 迭代随机——>5 份备案时每次运行展示的
		// 子集与顺序都不同（Python list(dict.items())[:5] 保持 sorted(glob)
		// 插入序，输出确定）。按域名排序取前 5，恢复可复现性。
		doms := make([]string, 0, len(icp))
		for dom := range icp {
			doms = append(doms, dom)
		}
		sort.Strings(doms)
		if len(doms) > 5 {
			doms = doms[:5]
		}
		for _, dom := range doms {
			dv := icp[dom]
			d, _ := dv.(map[string]any)
			icpNo := strings.TrimSpace(strOrDash(d["icp"]))
			unit := strings.TrimSpace(strOrDash(d["unit"]))
			// 纵深防御：不信任"看似 filed 实则脏数据"的记录（report.py:82-87）
			filed, _ := d["filed"].(bool)
			valid := filed && icpNo != "" && !strings.Contains(icpNo, "查询失败") && !strings.Contains(unit, "查询失败")
			if valid {
				a(fmt.Sprintf("| ICP（%s） | %s · %s · %s · %s |", dom, icpNo, unit, dashV(d["type"]), dashV(d["time"])))
			} else {
				msg := strOrDash(d["msg"])
				if msg == "" {
					msg = "接口未返回有效数据，建议人工复核"
				}
				a(fmt.Sprintf("| ICP（%s） | 未查询到有效备案信息（%s） |", dom, msg))
			}
		}
		a("")
	}

	subs := strList(b["subdomains"])
	liveRows := anyList(b["subdomains_live"])
	var aliveRows []map[string]any
	for _, r := range liveRows {
		if rm, ok := r.(map[string]any); ok {
			if ab, _ := rm["alive"].(bool); ab {
				aliveRows = append(aliveRows, rm)
			}
		}
	}
	if len(subs) > 0 || len(aliveRows) > 0 {
		a("## 2. 子域与存活\n")
		httpCnt := 0
		for _, r := range aliveRows {
			h, _ := r["http"].(map[string]any)
			if h != nil && numOf(h["status"]) != 0 { // Python truthy: status 非 0/None
				httpCnt++
			}
		}
		a(fmt.Sprintf("- 枚举 %d 个；DNS 可解析 **%d** 个；其中 %d 个有 HTTP 响应",
			len(subs), len(aliveRows), httpCnt))
		if len(aliveRows) > 0 {
			a("\n| 子域 | IP | HTTP | 标题 |")
			a("|---|---|---|---|")
			rows := aliveRows
			if len(rows) > 30 {
				rows = rows[:30]
			}
			for _, r := range rows {
				h, _ := r["http"].(map[string]any)
				scheme, status := "-", "-"
				title := ""
				if h != nil {
					if v := strV(h["scheme"]); v != "" {
						scheme = v
					}
					if st := numOf(h["status"]); st != 0 {
						status = fmt.Sprintf("%d", st)
					}
					title = strV(h["title"])
					tr := []rune(title)
					if len(tr) > 40 {
						tr = tr[:40]
					}
					title = string(tr)
				}
				ips := strList(r["ips"])
				if len(ips) > 2 {
					ips = ips[:2]
				}
				a(fmt.Sprintf("| %s | %s | %s %s | %s |", r["host"], strings.Join(ips, ","), scheme, status, title))
			}
			if len(aliveRows) > 30 {
				a(fmt.Sprintf("| … | 其余 %d 条见 `subdomains_live.json` | | |", len(aliveRows)-30))
			}
		}
		a("")
	}

	fp := anyList(b["fingerprint"])
	if len(fp) > 0 {
		a("## 3. 指纹识别\n")
		a("| 命中 | 类型 |")
		a("|---|---|")
		for _, f := range fp {
			fm, _ := f.(map[string]any)
			a(fmt.Sprintf("| %s | %s |", fm["name"], fm["type"]))
		}
		a("")
	}

	pj, _ := b["paths"].(map[string]any)
	pjAlive := anyList(pj["alive"])
	if len(pjAlive) > 0 {
		a("## 4. 敏感路径（已复验）\n")
		a("| 路径 | 状态 | 大小 | 复验 |")
		a("|---|---|---|---|")
		for _, r := range pjAlive {
			rm, _ := r.(map[string]any)
			verdict := "未通过"
			if vb, _ := rm["verified"].(bool); vb {
				verdict = "通过"
			}
			a(fmt.Sprintf("| %s | %v | %vB | %s |", rm["path"], rm["status"], rm["size"], verdict))
		}
		bl, _ := pj["baseline"].(map[string]any)
		kind, _ := bl["kind"].(string)
		switch kind {
		case "soft404", "uniform403", "redirect":
			a(fmt.Sprintf("\n> 注：该站存在 catch-all（%s），形态一致的响应已被剔除。", kind))
		}
		a("")
	}

	aj, _ := b["api"].(map[string]any)
	hits := anyList(aj["hits"])
	if len(hits) > 0 {
		a("## 5. API 文档 / 未授权暴露\n")
		a("| 端点 | 名称 | 风险 | 存活复验 | 证据 |")
		a("|---|---|---|---|---|")
		for _, h := range hits {
			hm, _ := h.(map[string]any)
			state := "未通过 ✗"
			if hb, _ := hm["live"].(bool); hb {
				state = "存活 ✓"
			}
			evCell := "—"
			if ev, ok := hm["evidence_dir"].(string); ok && ev != "" {
				clean := strings.TrimRight(ev, string(filepath.Separator))
				if rel, err := filepath.Rel(filepath.Dir(clean), clean); err == nil {
					evCell = "`" + rel + "`"
				}
			}
			a(fmt.Sprintf("| `%s` | %s | %s | %s | %s |",
				hm["path"], hm["name"], hm["risk"], state, evCell))
		}
		a(fmt.Sprintf("\n> catch-all 过滤：%d 条疑似被剔除；存活命中 %d 个（证据已落盘，**勿直接外传，脱敏后引用**）",
			numOf(aj["soft404_filtered"]), numOf(aj["live_hits"])))
		a("")
	}

	js, _ := b["jsintel"].(map[string]any)
	jsEndpoints := anyList(js["endpoints"])
	jsSensitive := anyList(js["sensitive"])
	jsDomains, _ := js["domains"].(map[string]any)
	hasDomains := false
	for _, v := range jsDomains {
		if l := anyList(v); len(l) > 0 {
			hasDomains = true
		}
	}
	if len(jsEndpoints) > 0 || len(jsSensitive) > 0 || hasDomains {
		a("## 6. JS 线索（jsintel，前端接口挖掘）\n")
		sc, _ := js["scripts"].(map[string]any)
		a(fmt.Sprintf("- 页面状态 %v；外链 JS 下载成功 %v/%v，内联 %v 段；端点线索 **%d** 条",
			js["page_status"], sc["downloaded"], sc["external"], sc["inline"], len(jsEndpoints)))
		full := anyList(js["endpoints_full"])
		top := full
		if len(top) > 15 {
			top = top[:15]
		}
		for _, u := range top {
			a(fmt.Sprintf("  - `%v`", u))
		}
		if len(full) > 15 {
			a(fmt.Sprintf("  - … 其余 %d 条见 `jsintel.json`", len(full)-15))
		}
		if len(jsSensitive) > 0 {
			a(fmt.Sprintf("\n敏感线索 %d 处（**值已打码，仅位置提示**，线索≠漏洞，需人工复核）：\n", len(jsSensitive)))
			a("| 位置 | 键 | 值（打码） | 片段 |")
			a("|---|---|---|---|")
			sen := jsSensitive
			if len(sen) > 20 {
				sen = sen[:20]
			}
			for _, s := range sen {
				sm, _ := s.(map[string]any)
				sn := strV(sm["snippet"])
				sr := []rune(sn)
				if len(sr) > 40 {
					sr = sr[:40]
				}
				a(fmt.Sprintf("| `%v:%v` | %s | %s | `%s` |", sm["file"], sm["line"], sm["key"], sm["value"], string(sr)))
			}
		}
		if jsDomains != nil {
			subN := len(anyList(jsDomains["subdomains"]))
			thirdN := len(anyList(jsDomains["thirdparty"]))
			ipN := len(anyList(jsDomains["internal_ips"]))
			subs2 := strList(jsDomains["subdomains"])
			top := subs2
			if len(top) > 8 {
				top = top[:8]
			}
			joined := strings.Join(top, ", ")
			if joined == "" {
				joined = "-"
			}
			a(fmt.Sprintf("\n- 域名线索：子域/同域 %d 个（%s）· 第三方域 %d 个 · 内网 IP %d 个", subN, joined, thirdN, ipN))
		}
		a("")
	}

	pj2, _ := b["ports"].(map[string]any)
	openRows := anyList(pj2["open"])
	if len(openRows) > 0 {
		ipCell := "未解析"
		if v := strV(pj2["ip"]); v != "" {
			ipCell = v
		}
		a("## 7. 开放端口（portscan，常用端口表）\n")
		a(fmt.Sprintf("- 目标 %v（%s），扫描 %v 个端口，开放 **%d** 个\n", pj2["target"], ipCell, pj2["scanned"], len(openRows)))
		a("| 端口 | 服务 | banner（截断） |")
		a("|---|---|---|")
		rows := openRows
		if len(rows) > 40 {
			rows = rows[:40]
		}
		for _, r := range rows {
			rm, _ := r.(map[string]any)
			svc := strV(rm["service"])
			if svc == "" {
				svc = "-"
			}
			bn := strV(rm["banner"])
			br := []rune(bn)
			if len(br) > 40 {
				br = br[:40]
			}
			a(fmt.Sprintf("| %v | %s | %s |", rm["port"], svc, string(br)))
		}
		a("")
	}

	if s := strV(b["llm_summary"]); s != "" {
		a("## 8. LLM 辅助小结\n")
		a(s)
		a("")
	}

	a("## 待人工跟进\n")
	a("- [ ] 对上述存活项逐条复核（复核命令见各证据目录 `repro.md`）")
	a("- [ ] 对未复验通过的疑似项降低优先级，避免写进报告")
	a("- [ ] 结论只写实测内容；推演内容必须标注【推演】")
	return strings.Join(L, "\n")
}

// PackEvidence 把 out/evidence/ 打包成 zip，对齐 report.py:192-209：
// Deflate、文件名 evidence-<safe48>-<YYYYMMDD-HHMMSS>.zip、arcname 相对 out/
// （禁绝对路径与 ..）；无 evidence 目录或空 → 返回 ""。
func PackEvidence(out, target string) string {
	src := filepath.Join(out, "evidence")
	st, err := os.Stat(src)
	if err != nil || !st.IsDir() {
		return ""
	}
	var files []string
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, c := range target {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' {
			sb.WriteRune(c)
		} else {
			sb.WriteRune('_')
		}
	}
	safe := []rune(sb.String())
	if len(safe) > 48 {
		safe = safe[:48]
	}
	if len(safe) == 0 {
		safe = []rune("target")
	}
	zipPath := filepath.Join(out, fmt.Sprintf("evidence-%s-%s.zip", string(safe), ZipStamp()))
	tmpZip := zipPath + ".part"
	zf, err := os.Create(tmpZip)
	if err != nil {
		return ""
	}
	w := zip.NewWriter(zf)
	defer w.Close()
	for _, fp := range files {
		rel, rerr := filepath.Rel(out, fp)
		if rerr != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			continue // 纵深防御：arcname 必须相对 out/ 且不得穿越
		}
		// zip 规范用正斜杠（Python zipfile.write 内部同样做 os.sep→"/" 规范化）
		rel = filepath.ToSlash(rel)
		// fix2 P2：'..' 子串（pwn_..%2F..%2Fwin.ini、dir_a..b/ 等）是合法文件名
		// 的一部分，不构成 zip 穿越——此前按子串整只跳过会静默丢证；穿越只
		// 可能由「段恰为 ..」构成（Rel 产物已被上方 HasPrefix/IsAbs 拦死），
		// 这里按段防御性复检，其余照收，杜绝证据包缺件无告警。
		unsafe := false
		for _, seg := range strings.Split(rel, "/") {
			if seg == ".." {
				unsafe = true
				break
			}
		}
		if unsafe {
			continue
		}
		data, rerr := os.ReadFile(fp)
		if rerr != nil {
			continue
		}
		hdr := &zip.FileHeader{Name: rel, Method: zip.Deflate, Modified: time.Now()}
		f, ferr := w.CreateHeader(hdr)
		if ferr != nil {
			continue
		}
		_, _ = f.Write(data)
	}
	// fix2 P2：先写 .part 再原子改名——并发/中途失败都不会留下截断的 zip
	if err := w.Close(); err != nil {
		zf.Close()
		os.Remove(tmpZip)
		return ""
	}
	if err := zf.Close(); err != nil {
		os.Remove(tmpZip)
		return ""
	}
	if err := os.Rename(tmpZip, zipPath); err != nil {
		os.Remove(tmpZip)
		return ""
	}
	return zipPath
}

// RunReport 幂等生成 report.md + 证据包，对齐 report.py:212-223。
func RunReport(out, target string) string {
	b := Collect(out, target)
	path, err := netutil.SafeWrite(out, "report.md", RenderMD(b))
	if err != nil {
		fmt.Printf("[!] report.md 写盘失败: %v\n", err)
		return ""
	}
	fmt.Printf("[+] 资产档案已生成 -> %s\n", path)
	zp := PackEvidence(out, target)
	if zp != "" {
		if st, serr := os.Stat(zp); serr == nil {
			n := zipEntryCount(zp)
			fmt.Printf("[+] 证据包已打包（%d 个文件，%.1f KB）-> %s\n", n, float64(st.Size())/1024, zp)
		}
	} else {
		fmt.Println("[*] 本次没有落盘证据（无存活命中），跳过证据包")
	}
	return path
}

func zipEntryCount(path string) int {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0
	}
	defer zr.Close()
	return len(zr.File)
}

// ── 渲染小工具（Python 语义对齐）──

func strV(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// numOf 通用数值提取：JSON 反序列化是 float64，测试/调用方可传 int——统一取 int。
func numOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func strOrDash(v any) string {
	if s := strV(v); s != "" {
		return s
	}
	return ""
}

func dashV(v any) string {
	if s := strV(v); s != "" {
		return s
	}
	return "-"
}

func strList(v any) []string {
	l, _ := v.([]string)
	if l != nil {
		return l
	}
	var out []string
	if la, ok := v.([]any); ok {
		for _, x := range la {
			out = append(out, strV(x))
		}
	}
	return out
}

// anyList 列表归一：JSON 反序列化产物是 []any，测试/调用方可传 []string 或
// []map[string]any——三种都转成 []any，渲染逻辑统一走 map 访问。
func anyList(v any) []any {
	switch l := v.(type) {
	case []any:
		return l
	case []string:
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	case []map[string]any:
		out := make([]any, len(l))
		for i, m := range l {
			out[i] = m
		}
		return out
	}
	return nil
}
