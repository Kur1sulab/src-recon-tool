// Package server 桌面端本地 HTTP 服务：六接口 + 前端静态资源。
// 只由 main 绑定 127.0.0.1 暴露；所有响应 no-store；错误统一 JSON。
// 本包不直接创建任何进程：扫描经 engine.Runner，解释器探测走 Runner.ProbePython。
package server

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"recon-desktop/internal/engine"
	"recon-desktop/internal/store"
	"recon-desktop/internal/whitelist"
)

// Deps 服务依赖。Frontend 为嵌入的前端文件系统（frontend/ 子目录）。
type Deps struct {
	Store    *store.Store
	Runner   *engine.Runner
	RepoRoot string
	DataDir  string
	Frontend fs.FS
}

type server struct {
	deps Deps
}

// New 组装 HTTP 处理器（Go 1.22 method+path 路由）。
func New(d Deps) http.Handler {
	s := &server{deps: d}
	if d.Runner != nil {
		// 引擎状态/进度 → 任务库（监视 goroutine 经此回写）
		d.Runner.SetSink(storeSink{st: d.Store})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/env", s.hEnv)
	mux.HandleFunc("POST /api/scans", s.hCreate)
	mux.HandleFunc("GET /api/scans", s.hList)
	mux.HandleFunc("GET /api/scans/{id}", s.hDetail)
	mux.HandleFunc("POST /api/scans/{id}/stop", s.hStop)
	mux.HandleFunc("GET /api/scans/{id}/evidence", s.hEvidence)
	mux.HandleFunc("DELETE /api/scans/{id}", s.hDelete)
	mux.HandleFunc("/", s.hStatic)
	return noStore(localGuard(mux))
}

// ── 基础设施 ──

// localGuard 本机边界：
//   - Host 只认环回（127.0.0.1 / localhost / ::1）——封本机 DNS rebinding
//     让远端网页读取任务历史的读取面；
//   - 带 Origin 头的请求必须与 Host 同源——封本机任意网页用 no-cors 简单
//     请求（text/plain 表单免预检）盲打 POST 起停扫描。
//
// 只绑 127.0.0.1 是监听层约束，这里是请求层复核，两层独立成立。
func localGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			writeErr(w, 403, "非本机请求（Host 不合法），已拒绝")
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != r.Host {
				writeErr(w, 403, "跨站请求（Origin 不合法），已拒绝")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		h.Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeHTTPErr(w http.ResponseWriter, code int, format string, a ...any) {
	writeErr(w, code, fmt.Sprintf(format, a...))
}

// storeSink 把引擎回调翻译成任务库写操作。
type storeSink struct{ st *store.Store }

func (s storeSink) AppendProgress(id string, evs []store.ProgressEvent) {
	s.st.AppendProgress(id, evs)
}

func (s storeSink) SetStatus(id, status string, exitCode *int) {
	_ = s.st.Update(id, func(t *store.Task) {
		// 终态不回退：hStop 幂等分支/崩溃对账已落终态后，monitor 收尾
		// （wasStopping 读取与落终态之间无锁）不得把 stopped 改写成 fail
		switch t.Status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			return
		}
		t.Status = status
		t.ExitCode = exitCode
		switch status {
		case store.StatusDone, store.StatusFail, store.StatusStopped:
			t.FinishedAt = float64(time.Now().UnixMilli()) / 1e3
		}
	})
}

// ── GET /api/env ──

func (s *server) hEnv(w http.ResponseWriter, r *http.Request) {
	found, version, depsOK := s.deps.Runner.ProbePython()
	pyPath, _ := s.deps.Runner.ResolvePython()
	out := map[string]any{
		"python": map[string]any{
			"found":   found,
			"path":    pyPath,
			"version": version,
			"deps_ok": depsOK,
		},
		"out_dir":        filepath.Join(s.deps.RepoRoot, "out"),
		"mock_reachable": mockReachable(),
		"whitelist":      whitelist.Entries,
	}
	writeJSON(w, 200, out)
}

// mockReachable 探测本机 mock 靶站（127.0.0.1:8799，白名单内的授权目标）。
func mockReachable() bool {
	c := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := c.Get("http://127.0.0.1:8799/")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// ── POST /api/scans ──

type createReq struct {
	Target string `json:"target"`
	Cmd    string `json:"cmd"`
	Args   string `json:"args"`
}

var argsTokenRe = regexp.MustCompile(`^[A-Za-z0-9_.=,:/+@%^-]+$`)

// targetFlagTokens recon.py 各子解析器的目标旗标同义全集：目标只能由壳按
// 白名单校验后注入，args 里出现同名/同义旗标一律拒绝——否则 argparse
// "重复单值旗标后者胜"，用户 args 可覆盖受控目标、扫描名单外资产。
var targetFlagTokens = map[string]bool{
	"-u": true, "--url": true, "-t": true, "--target": true,
	"-d": true, "--domain": true, "-i": true, "--ip": true,
}

// flagName 取旗标名（截掉 =value，小写）。
func flagName(tk string) string {
	if i := strings.IndexByte(tk, '='); i >= 0 {
		tk = tk[:i]
	}
	return strings.ToLower(tk)
}

func (s *server) hCreate(w http.ResponseWriter, r *http.Request) {
	var req createReq
	body := http.MaxBytesReader(w, r.Body, 8<<10)
	dec := json.NewDecoder(body)
	if err := dec.Decode(&req); err != nil {
		writeHTTPErr(w, 400, "请求体不是合法 JSON: %v", err)
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Cmd = strings.TrimSpace(req.Cmd)
	if req.Target == "" {
		writeErr(w, 400, "缺少扫描目标")
		return
	}
	if len(req.Target) > 200 {
		writeErr(w, 400, "目标过长（上限 200 字符）")
		return
	}
	if !engine.CmdAllowed(req.Cmd) {
		writeErr(w, 400, "不支持的子命令: "+req.Cmd)
		return
	}
	// 白名单闸：名单外一律 403（正点名单硬校验）
	if _, err := whitelist.Check(req.Target); err != nil {
		writeErr(w, 403, "目标不在授权白名单，已拒绝（允许: xycovo.com / 47.100.49.228 / 127.0.0.1:8799）")
		return
	}
	// 按子命令形态校验并归一目标
	target, err := normalizeTarget(req.Cmd, req.Target)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	extra, err := parseArgs(req.Args)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// fix1 P0 纵深层：按模块旗标精确白名单复检（堵 argparse 前缀缩写展开
	// --ur→--url 等 last-wins 目标覆盖；黑名单只认全名，拦不住缩写）。
	if err := engine.ValidateExtraArgs(req.Cmd, extra); err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	id := genID()
	now := float64(time.Now().UnixMilli()) / 1e3
	task := &store.Task{
		ID:        id,
		Target:    target,
		Cmd:       req.Cmd,
		Args:      strings.Join(extra, " "),
		Status:    store.StatusCreated,
		CreatedAt: now,
		LogPath:   filepath.Join(s.deps.DataDir, "logs", id+".log"),
	}
	if err := s.deps.Store.Create(task); err != nil {
		writeHTTPErr(w, 500, "任务入库失败: %v", err)
		return
	}
	if err := s.deps.Runner.Start(id, req.Cmd, target, extra); err != nil {
		_ = s.deps.Store.Update(id, func(t *store.Task) {
			// 终态不回退：hStop 竞态（Start 放弃启动）已落 stopped 时不得改写成 fail
			switch t.Status {
			case store.StatusDone, store.StatusFail, store.StatusStopped:
				return
			}
			t.Status = store.StatusFail
			t.FinishedAt = float64(time.Now().UnixMilli()) / 1e3
			t.Progress = append(t.Progress, store.ProgressEvent{
				Ts: float64(time.Now().UnixMilli()) / 1e3, Module: "pipeline",
				Event: "pipeline_end", Detail: "fail",
			})
		})
		writeHTTPErr(w, 500, "启动扫描失败: %v", err)
		return
	}
	writeJSON(w, 200, map[string]string{"id": id, "status": "created"})
}

// normalizeTarget 按子命令校验形态；url 类缺协议时补 http://。
func normalizeTarget(cmd, target string) (string, error) {
	isURLCmd := cmd == "api" || cmd == "paths" || cmd == "fingerprint" || cmd == "jsintel"
	lower := strings.ToLower(target)
	switch {
	case isURLCmd:
		if !strings.Contains(lower, "://") {
			return "http://" + target, nil
		}
		return target, nil
	case cmd == "reverse":
		if strings.ContainsAny(target, "/:") || net.ParseIP(target) == nil {
			return "", fmt.Errorf("IP 反查的目标应为裸 IP 地址，如 47.100.49.228")
		}
		return target, nil
	case cmd == "subdomain" || cmd == "icp":
		if strings.ContainsAny(target, "/:") {
			return "", fmt.Errorf("该模块的目标应为域名（不含协议和端口），如 xycovo.com")
		}
		return target, nil
	default: // all / portscan
		if strings.Contains(lower, "://") {
			return "", fmt.Errorf("该模块的目标应为域名或 IP（不含协议）")
		}
		return target, nil
	}
}

// parseArgs 把可选参数串切成 argv 白名单片段：限长、限量、限字符集，
// 并显式挡掉 --progress-file（由壳注入，用户不可覆盖）。
func parseArgs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 200 {
		return nil, fmt.Errorf("可选参数过长（上限 200 字符）")
	}
	tokens := strings.Fields(raw)
	if len(tokens) > 8 {
		return nil, fmt.Errorf("可选参数最多 8 段")
	}
	for _, tk := range tokens {
		lower := strings.ToLower(tk)
		// 前缀匹配：--progress-file=x 等号形式与下划线形式一并挡掉
		if strings.HasPrefix(lower, "--progress-file") || strings.HasPrefix(lower, "--progress_file") ||
			lower == "-h" || lower == "--help" {
			return nil, fmt.Errorf("不允许的参数: %s", tk)
		}
		if targetFlagTokens[flagName(tk)] {
			return nil, fmt.Errorf("目标由系统按白名单校验后注入，不允许在可选参数中指定: %s", tk)
		}
		if !argsTokenRe.MatchString(tk) {
			return nil, fmt.Errorf("参数含不允许的字符: %s", tk)
		}
	}
	return tokens, nil
}

// maxEvidenceFile 聚合 zip 时单文件大小上限（测试可调小）。
var maxEvidenceFile int64 = 64 << 20

// genID 生成任务 ID。
func genID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// ── GET /api/scans ──

func (s *server) hList(w http.ResponseWriter, r *http.Request) {
	tasks := s.deps.Store.List()
	out := make([]map[string]any, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, map[string]any{
			"id": t.ID, "target": t.Target, "cmd": t.Cmd, "args": t.Args,
			"status": t.Status, "created_at": t.CreatedAt,
			"finished_at": t.FinishedAt,
		})
	}
	writeJSON(w, 200, map[string]any{"scans": out})
}

// ── GET /api/scans/{id} ──

func (s *server) hDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.deps.Store.Get(id)
	if !ok {
		writeErr(w, 404, "任务不存在或已被清理")
		return
	}
	artifacts, evidence := s.collectArtifacts(task.Target)
	progress := task.Progress
	if progress == nil {
		progress = []store.ProgressEvent{}
	}
	writeJSON(w, 200, map[string]any{
		"id": task.ID, "target": task.Target, "cmd": task.Cmd, "args": task.Args,
		"status": task.Status, "created_at": task.CreatedAt,
		"finished_at": task.FinishedAt, "exit_code": task.ExitCode,
		"progress": progress, "artifacts": artifacts,
		"log_tail": s.logTail(task.LogPath), "evidence_path": evidence,
	})
}

// outDirSanitizer 产物目录名清洗：与引擎 MakeOutdir（engine-go/internal/cli）
// 及 Python make_outdir（src/recon.py）三方同规则（fix1 P1）——://、/、\、:、
// Windows 非法字符 ?&="<|>* 全部换 _，再剔首尾点/空格；空与 ".." 回 "unknown"。
// 三处必须产出同名目录，否则桌面壳在 out/ 下找不到引擎产物。
var outDirSanitizer = strings.NewReplacer(
	"://", "_", "/", "_", "\\", "_", ":", "_",
	"?", "_", "&", "_", "=", "_", `"`, "_",
	"<", "_", ">", "_", "|", "_", "*", "_",
)

// winReservedStems Windows 保留设备名主干（与引擎 netutil.DefuseWindowsReservedStem
// 同集——跨 Go module 无法复用，此处按值同步；三方任一改动须四处同改）。
var winReservedStems = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// outDirFor 目标 → 产物目录（替换规则与 Python make_outdir 完全一致，
// fix2 P3：含设备名主干补 _，否则壳在 out/ 下找不到引擎产物）。
func outDirFor(repoRoot, target string) string {
	name := strings.Trim(outDirSanitizer.Replace(target), ". ")
	if name == "" || name == ".." {
		name = "unknown"
	}
	stem, ext := name, ""
	if i := strings.Index(name, "."); i >= 0 {
		stem, ext = name[:i], name[i:]
	}
	if winReservedStems[strings.ToLower(stem)] {
		name = stem + "_" + ext
	}
	return filepath.Join(repoRoot, "out", name)
}

// collectArtifacts 产物清单（文件名+大小，≤200 条）+ 现成 evidence zip 路径。
func (s *server) collectArtifacts(target string) ([]map[string]any, string) {
	dir := outDirFor(s.deps.RepoRoot, target)
	out := []map[string]any{}
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // 目录不存在等一律静默
		}
		files = append(files, path)
		return nil
	})
	sort.Strings(files)
	if len(files) > 200 {
		files = files[:200]
	}
	evidence := ""
	var newest time.Time
	for _, p := range files {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		lower := strings.ToLower(rel)
		if strings.HasPrefix(lower, "evidence-") && strings.HasSuffix(lower, ".zip") {
			if evidence == "" || info.ModTime().After(newest) {
				evidence = p
				newest = info.ModTime()
			}
		}
		out = append(out, map[string]any{"name": filepath.ToSlash(rel), "size": info.Size()})
	}
	return out, evidence
}

// logTail 日志文件尾部（≤8KB，原样返回不解析）。
func (s *server) logTail(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	const keep = 8 << 10
	data, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	if len(data) > keep {
		data = data[len(data)-keep:]
	}
	return string(data)
}

// ── POST /api/scans/{id}/stop ──

func (s *server) hStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.deps.Store.Get(id)
	if !ok {
		writeErr(w, 404, "任务不存在或已被清理")
		return
	}
	if task.Status == store.StatusRunning || task.Status == store.StatusCreated {
		// 进程表里已无此 ID（崩溃残留/恰好退出）→ 按幂等成功处理并落终态，
		// 不再 409——否则重启后僵尸 running 任务永远无法清除。
		// created 同样受理：前端对 created/running 都渲染停止按钮，
		// 静默吞掉会让用户看到"已提交"而任务照常跑完。
		if err := s.deps.Runner.Stop(id); err != nil && !errors.Is(err, engine.ErrNotRunning) {
			writeHTTPErr(w, 409, "停止失败: %v", err)
			return
		}
		// 终态由引擎监视 goroutine 兜底；这里先标防窗口期重复操作
		_ = s.deps.Store.Update(id, func(t *store.Task) {
			if t.Status == store.StatusRunning || t.Status == store.StatusCreated {
				t.Status = store.StatusStopped
				t.FinishedAt = float64(time.Now().UnixMilli()) / 1e3
			}
		})
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ── DELETE /api/scans/{id} ──
//
// 删除任务记录与数据目录文件；out/ 产物保留在盘（用户资产，前端确认文案明示）。

func (s *server) hDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.deps.Store.Get(id); !ok {
		writeErr(w, 404, "任务不存在或已被清理")
		return
	}
	if err := s.deps.Store.Delete(id); err != nil {
		if errors.Is(err, store.ErrTaskActive) {
			writeErr(w, 409, "任务仍在运行，请先停止再删除")
			return
		}
		writeHTTPErr(w, 500, "删除失败: %v", err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ── GET /api/scans/{id}/evidence ──

func (s *server) hEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, ok := s.deps.Store.Get(id)
	if !ok {
		writeErr(w, 404, "任务不存在或已被清理")
		return
	}
	_, evidence := s.collectArtifacts(task.Target)
	// fix1 P2：out/ 内现成的 evidence-*.zip 不再盲目信任——先审计条目名
	//（拒绝 ../ 段、前导 /、盘符、反斜杠），不安全则弃用并落到下方现打分支
	//（现打分支的条目名全部来自 filepath.Rel，结构安全）。服务端自身不解包，
	// 但把可疑压缩包原样推给最终用户的解压工具等于转嫁风险。
	if evidence != "" && evidenceZipSafe(evidence) {
		data, err := os.ReadFile(evidence)
		if err == nil {
			serveZip(w, data)
			return
		}
	}
	// 无现成 evidence-*.zip → 现打聚合 zip，避免导出按钮空转
	dir := outDirFor(s.deps.RepoRoot, task.Target)
	// 防目录穿越：解析后必须仍在 out/ 前缀内
	outRoot, err := filepath.Abs(filepath.Join(s.deps.RepoRoot, "out"))
	if err != nil {
		writeErr(w, 500, "解析 out 目录失败")
		return
	}
	absDir, err := filepath.Abs(dir)
	if err != nil || !strings.HasPrefix(absDir, outRoot+string(filepath.Separator)) {
		writeErr(w, 400, "非法的产物目录")
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	count := 0
	var skipped []string
	_ = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || count >= 500 {
			return nil
		}
		rel, rerr := filepath.Rel(absDir, path)
		if rerr != nil {
			return nil
		}
		// P3：产物目录里的任意 zip（含被 evidenceZipSafe 审计弃用的毒 zip
		// 本体）一律不内嵌进新包——内嵌压缩包等于把其中未审计的条目原样
		// 转交给最终解压工具。如需取用请直接到产物目录拿原文件。
		if strings.EqualFold(filepath.Ext(rel), ".zip") {
			skipped = append(skipped, fmt.Sprintf("%s（压缩包不做内嵌重打包，未写入本压缩包）",
				filepath.ToSlash(rel)))
			return nil
		}
		// 超限文件整只跳过并留痕，绝不写截断字节——截断条目是损坏的
		// 证据，对以取证为名的导出是完整性问题。
		if info, serr := d.Info(); serr == nil && info.Size() > maxEvidenceFile {
			skipped = append(skipped, fmt.Sprintf("%s（%d 字节，超单文件上限 %d 字节，未打包）",
				filepath.ToSlash(rel), info.Size(), maxEvidenceFile))
			return nil
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil
		}
		defer f.Close()
		fw, zerr := zw.Create(filepath.ToSlash(rel))
		if zerr != nil {
			return nil
		}
		_, _ = io.Copy(fw, f)
		count++
		return nil
	})
	if len(skipped) > 0 { // 跳过清单随包留痕，导出者可感知
		if fw, zerr := zw.Create("_跳过的大文件.txt"); zerr == nil {
			_, _ = io.WriteString(fw, "以下文件未写入本压缩包（可到产物目录直接取原文件）：\n"+
				strings.Join(skipped, "\n")+"\n")
		}
	}
	zw.Close()
	if count == 0 && len(skipped) == 0 { // 空 zip 也有 22 字节 EOCD，必须按条目数判空
		writeErr(w, 404, "暂无产物可打包（任务可能还没跑出任何文件）")
		return
	}
	serveZip(w, buf.Bytes())
}

// evidenceZipSafe 审计现成 zip 的条目名安全性：任一条目含 ".." 段、前导 "/"、
// 盘符（如 C:）、反斜杠或空名即判不安全（zip 规范用 /，反斜杠本身即嫌疑）。
func evidenceZipSafe(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 512<<20 { // 审计对象限 512MB，防异常巨包
		return false
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return false
	}
	for _, zf := range zr.File {
		name := zf.Name
		if name == "" {
			return false
		}
		if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
			return false
		}
		if len(name) >= 2 && name[1] == ':' { // 盘符
			return false
		}
		for _, seg := range strings.Split(name, "/") {
			if seg == ".." {
				return false
			}
		}
	}
	return true
}

func serveZip(w http.ResponseWriter, data []byte) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// ── 静态资源（嵌入的前端）──

// apiFallback /api/ 前缀的兜底：已知资源形状但方法不匹配 → 405 + Allow；
// 真正未知的路径 → 404。
var apiShapes = []struct {
	allow string
	match func(rest []string) bool
}{
	{"GET", func(r []string) bool { return len(r) == 1 && r[0] == "env" }},
	{"GET, POST", func(r []string) bool { return len(r) == 1 && r[0] == "scans" }},
	{"GET", func(r []string) bool { return len(r) == 2 && r[0] == "scans" && r[1] != "" }},
	{"POST", func(r []string) bool { return len(r) == 3 && r[0] == "scans" && r[1] != "" && r[2] == "stop" }},
	{"GET", func(r []string) bool { return len(r) == 3 && r[0] == "scans" && r[1] != "" && r[2] == "evidence" }},
}

func (s *server) apiFallback(w http.ResponseWriter, r *http.Request) {
	rest := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[1:]
	for _, sh := range apiShapes {
		if sh.match(rest) {
			w.Header().Set("Allow", sh.allow)
			writeErr(w, 405, "该方法不支持")
			return
		}
	}
	writeErr(w, 404, "未知接口")
}

func (s *server) hStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		s.apiFallback(w, r)
		return
	}
	if s.deps.Frontend == nil {
		http.Error(w, "前端资源未嵌入", http.StatusNotImplemented)
		return
	}
	// 隐藏目录/文件（.mimosa 等工具内部产物）一律 404，不做 SPA 兜底
	for _, seg := range strings.Split(r.URL.Path, "/") {
		if len(seg) > 1 && seg[0] == '.' {
			writeErr(w, 404, "未知接口")
			return
		}
	}
	if name := strings.TrimPrefix(r.URL.Path, "/"); name != "" {
		if data, err := fs.ReadFile(s.deps.Frontend, name); err == nil {
			http.ServeContent(w, r, filepath.Base(name), time.Time{}, bytes.NewReader(data))
			return
		}
	}
	// SPA 用 hash 路由；未命中的路径直接回 index.html 字节。
	// 不能改写路径后交给 http.FileServer：它对指向 index.html 的请求会
	// 302 回目录（./），与根路径改写互相成环 → / → ./ → / 重定向死循环。
	data, err := fs.ReadFile(s.deps.Frontend, "index.html")
	if err != nil {
		http.Error(w, "前端资源未嵌入", http.StatusNotImplemented)
		return
	}
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(data))
}
