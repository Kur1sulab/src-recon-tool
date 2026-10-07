package cli

// baseline_cli_test.go — baseline 子命令契约（桌面执行器裁决的第二子进程入口）：
//   - 命令行契约：<recon-go> --progress-file <f> baseline -d <域名> [--checks c1,c2]
//     （--progress-file 全局参数在子命令之前；-u 可选，缺省 PickBase 推导）
//   - 事件契约：pipeline_start(baseline) → start(baseline) → 内层每检查
//     start/done|fail → done(baseline) → pipeline_end(pipeline,done|fail)；
//     个别检查 fail 不改变聚合终态（exit 0）
//   - 未知检查名 / 域名形状非法 → exit 2；缺 -d → exit 2
// 离线：demo.test 为 RFC6761 保留 TLD（不解析、不出网）；集成用例打
// mockweb（127.0.0.1）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/mockweb"
)

// runBaseline 辅助：带进度文件跑 baseline，返回退出码与事件列表。
// progressFile 是包级变量（Run 经 --progress-file 设置）——保存/恢复，
// 防污染同包后续测试（fix1 的环境变量兜底用例依赖其为空）。
func runBaseline(t *testing.T, args ...string) (int, []map[string]any) {
	t.Helper()
	old := progressFile
	t.Cleanup(func() { progressFile = old })
	dir := t.TempDir()
	pf := filepath.Join(dir, "progress.jsonl")
	code := Run(append([]string{"--progress-file", pf}, args...))
	return code, readJSONL(t, pf)
}

func TestBaselineMissingDomain(t *testing.T) {
	code, _ := runBaseline(t, "baseline")
	if code != 2 {
		t.Errorf("缺 -d 应 exit 2, 得 %d", code)
	}
}

func TestBaselineBadDomainShape(t *testing.T) {
	code, _ := runBaseline(t, "baseline", "-d", "bad/../dom")
	if code != 2 {
		t.Errorf("域名形状非法应 exit 2, 得 %d", code)
	}
}

func TestBaselineUnknownCheck(t *testing.T) {
	// 未知检查名在校验阶段即拒（exit 2），且不发任何网络请求
	code, _ := runBaseline(t, "baseline", "-d", "demo.test", "--checks", "secheaders,nope")
	if code != 2 {
		t.Errorf("未知检查名应 exit 2, 得 %d", code)
	}
}

func TestBaselineEventsCheckFailDoesNotBreakTerminal(t *testing.T) {
	// demo.test 不解析 → secheaders 入口校验失败 → 内层 fail 事件；
	// 聚合终态仍 done（exit 0）——桌面 monitor 判据不变
	code, events := runBaseline(t, "baseline", "-d", "demo.test", "--checks", "secheaders")
	if code != 0 {
		t.Fatalf("检查级失败不应改变退出码, 得 %d", code)
	}
	seq := make([]string, 0, len(events))
	for _, e := range events {
		seq = append(seq, e["event"].(string)+"/"+e["module"].(string))
	}
	joined := strings.Join(seq, " ")
	for _, want := range []string{
		"pipeline_start/pipeline", "start/baseline", "start/secheaders",
		"fail/secheaders", "done/baseline", "pipeline_end/pipeline",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("事件序缺 %s: %v", want, seq)
		}
	}
	// 最后一条应为 pipeline_end/pipeline/done
	last := events[len(events)-1]
	if last["event"] != "pipeline_end" || last["detail"] != "done" {
		t.Errorf("终态应为 done: %v", last)
	}
	// 失败检查也要落盘 error 包络（桌面失败态）
	wd, _ := os.Getwd()
	b, err := os.ReadFile(filepath.Join(wd, "out", "demo.test", "secheaders.json"))
	if err != nil {
		t.Fatalf("secheaders.json 缺失: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["error"] == nil || m["error"] == "" {
		t.Errorf("失败包络应含 error: %s", b)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(wd, "out")) })
}

func TestBaselineMockwebEndToEnd(t *testing.T) {
	// 全链路集成：CLI → baseline 聚合 → secheaders/webfiles 打 127.0.0.1 靶站
	srv := mockweb.New()
	defer srv.Close()
	code, events := runBaseline(t, "baseline", "-d", "secexample.com",
		"-u", srv.URL+"/sec", "--checks", "secheaders,webfiles")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	seq := make([]string, 0, len(events))
	for _, e := range events {
		seq = append(seq, e["event"].(string)+"/"+e["module"].(string))
	}
	joined := strings.Join(seq, " ")
	if !strings.Contains(joined, "done/secheaders") || !strings.Contains(joined, "done/webfiles") {
		t.Errorf("两检查应 done: %v", seq)
	}
	wd, _ := os.Getwd()
	defer os.RemoveAll(filepath.Join(wd, "out"))
	// 产物：json + txt + evidence 副本 + paths_extra
	for _, p := range []string{
		filepath.Join(wd, "out", "secexample.com", "secheaders.json"),
		filepath.Join(wd, "out", "secexample.com", "webfiles.json"),
		filepath.Join(wd, "out", "secexample.com", "webfiles.txt"),
		filepath.Join(wd, "out", "secexample.com", "paths_extra.txt"),
		filepath.Join(wd, "out", "secexample.com", "evidence", "baseline", "secheaders.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("产物缺失: %s", p)
		}
	}
	// secheaders 产物内容抽检：jsonx.Pretty 缩进形态 + 包络结构键
	b, _ := os.ReadFile(filepath.Join(wd, "out", "secexample.com", "secheaders.json"))
	if !strings.Contains(string(b), `"check": "secheaders"`) || !strings.Contains(string(b), `"conclusion"`) {
		t.Errorf("包络结构缺失: %.200s", b)
	}
}

func TestBaselineInKnownCmds(t *testing.T) {
	if !knownCmds["baseline"] {
		t.Error("baseline 应在 knownCmds（事件流包层依赖）")
	}
	if !strings.Contains(helpText, "baseline -d") {
		t.Error("helpText 应含 baseline 用法行")
	}
}
