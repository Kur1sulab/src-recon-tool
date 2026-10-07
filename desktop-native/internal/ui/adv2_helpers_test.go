package ui

// adv2_helpers_test.go — 对抗轮测试小件：毒文件落盘 / 桩仓库 / 抽取任务 ID。

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}

func writeSettingsFile(dir, body string) error {
	return writeFile(filepath.Join(dir, "settings.json"), body)
}

// makeStubRepo 造一个含 engine-go/ 标记的假仓库根（终修轮：findRepoRoot
// 仓库根判据随直调重写改为 engine-go 目录，src/recon.py 桩退役）。
func makeStubRepo(repo string) error {
	return os.MkdirAll(filepath.Join(repo, "engine-go"), 0o755)
}

var advIDRe = regexp.MustCompile(`"id":"([^"]+)"`)

// taskIDOf 从毒 JSON 里抽第一个 id 值（毒文件本身未必是合法 JSON，用正则）。
func taskIDOf(body string) string {
	if m := advIDRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func itoa(i int) string { return strconv.Itoa(i) }
