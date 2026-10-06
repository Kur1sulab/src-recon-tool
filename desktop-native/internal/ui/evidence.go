package ui

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// evidence.go —— 证据包导出，规则自 desktop-go/internal/server 同语义移植：
// outDirFor 三方同名目录（Python make_outdir / engine-go / 本壳）、现成
// evidence zip 先审计再用、现打聚合包跳过嵌套 zip 与超限文件并留痕。

// maxEvidenceFile 聚合 zip 时单文件大小上限（测试可调小）。
var maxEvidenceFile int64 = 64 << 20

// outDirSanitizer 产物目录名清洗：与引擎 MakeOutdir 及 Python make_outdir
// 三方同规则——://、/、\、:、Windows 非法字符 ?&="<|>* 全部换 _，
// 再剔首尾点/空格；空与 ".." 回 "unknown"。
var outDirSanitizer = strings.NewReplacer(
	"://", "_", "/", "_", "\\", "_", ":", "_",
	"?", "_", "&", "_", "=", "_", `"`, "_",
	"<", "_", ">", "_", "|", "_", "*", "_",
)

// winReservedStems Windows 保留设备名主干（与引擎 netutil 同集——跨 module
// 无法复用，此处按值同步；三方任一改动须四处同改）。
var winReservedStems = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// outDirFor 目标 → 产物目录（替换规则与 Python make_outdir 完全一致，
// 含设备名主干补 _，否则壳在 out/ 下找不到引擎产物）。
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

// newestEvidenceZip 找产物目录里最新的现成 evidence-*.zip（无则空串）。
func newestEvidenceZip(dir string) string {
	var newest string
	var newestAt time.Time
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasPrefix(name, "evidence") || !strings.EqualFold(filepath.Ext(name), ".zip") {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.ModTime().After(newestAt) {
			newest, newestAt = path, info.ModTime()
		}
		return nil
	})
	return newest
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

// ExportEvidence 把任务的扫描产物打成证据包，落到 dataDir/evidence/<id>.zip。
// 优先复用产物目录里审计通过的现成 evidence-*.zip（mode="existing"），
// 否则现打聚合包（mode="packed"）：嵌套 zip 与超限文件跳过并随包留痕。
// 返回 导出路径 / 模式 / 打包条目数 / 跳过条目数 / 错误。
func (s *Session) ExportEvidence(id string) (path, mode string, packed, skipped int, err error) {
	task, ok := s.Store.Get(id)
	if !ok {
		return "", "", 0, 0, fmt.Errorf("任务不存在或已被清理")
	}
	dir := outDirFor(s.RepoRoot, task.Target)
	// 防目录穿越：解析后必须仍在 out/ 前缀内
	outRoot, aerr := filepath.Abs(filepath.Join(s.RepoRoot, "out"))
	if aerr != nil {
		return "", "", 0, 0, fmt.Errorf("解析 out 目录失败：%w", aerr)
	}
	absDir, aerr := filepath.Abs(dir)
	if aerr != nil || !strings.HasPrefix(absDir, outRoot+string(filepath.Separator)) {
		return "", "", 0, 0, fmt.Errorf("非法的产物目录")
	}

	destDir := filepath.Join(s.DataDir, "evidence")
	dest := filepath.Join(destDir, id+".zip")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", "", 0, 0, err
	}

	// 现成 evidence zip：审计通过才复用（毒 zip 原样转交等于转嫁风险）
	if existing := newestEvidenceZip(dir); existing != "" && evidenceZipSafe(existing) {
		if err := copyFile(existing, dest); err != nil {
			return "", "", 0, 0, err
		}
		return dest, "existing", 0, 0, nil
	}

	packed, skipped, err = packArtifacts(absDir, dest)
	if err != nil {
		return "", "", 0, 0, err
	}
	return dest, "packed", packed, skipped, nil
}

// packArtifacts 现打聚合包。返回打包/跳过条目数。
func packArtifacts(absDir, dest string) (packed, skipped int, err error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var notes []string
	count := 0
	_ = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || count >= 500 {
			return nil
		}
		rel, rerr := filepath.Rel(absDir, path)
		if rerr != nil {
			return nil
		}
		// 产物目录里的任意 zip 一律不内嵌进新包——内嵌压缩包等于把其中
		// 未审计的条目原样转交给最终解压工具。如需取用请直接到产物目录拿原文件。
		if strings.EqualFold(filepath.Ext(rel), ".zip") {
			notes = append(notes, fmt.Sprintf("%s（压缩包不做内嵌重打包，未写入本压缩包）", filepath.ToSlash(rel)))
			return nil
		}
		// 超限文件整只跳过并留痕，绝不写截断字节——截断条目是损坏的证据，
		// 对以取证为名的导出是完整性问题。
		if info, serr := d.Info(); serr == nil && info.Size() > maxEvidenceFile {
			notes = append(notes, fmt.Sprintf("%s（%d 字节，超单文件上限 %d 字节，未打包）",
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
	if len(notes) > 0 { // 跳过清单随包留痕，导出者可感知
		if fw, zerr := zw.Create("_跳过的大文件.txt"); zerr == nil {
			_, _ = io.WriteString(fw, "以下文件未写入本压缩包（可到产物目录直接取原文件）：\n"+
				strings.Join(notes, "\n")+"\n")
		}
	}
	if err := zw.Close(); err != nil {
		return 0, 0, err
	}
	if count == 0 && len(notes) == 0 { // 空 zip 也有 22 字节 EOCD，必须按条目数判空
		return 0, 0, fmt.Errorf("暂无产物可打包（任务可能还没跑出任何文件）")
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return 0, 0, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return 0, 0, err
	}
	return count, len(notes), nil
}

// copyFile 整文件复制（现成 zip 复用路径）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
