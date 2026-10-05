package paths

// extra_test.go — --extra 补充字典（report §5.2 验收 3）：webfiles 的
// paths_extra.txt（robots Disallow）回喂 paths 管线；合并去重断言。

import (
	"testing"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/mockweb"
)

func TestMergeExtra(t *testing.T) {
	// 去重、剔空、剔与内置字典重复项、保序
	got := mergeExtra([]string{"/swagger-ui.html", "/actuator/heapdump", "/swagger-ui.html", "", "  ", "/actuator/heapdump"})
	if len(got) != 1 || got[0] != "/actuator/heapdump" {
		t.Errorf("mergeExtra 应剔重剔空剔字典内项: %v", got)
	}
	if got := mergeExtra(nil); len(got) != 0 {
		t.Errorf("nil extra 应得空: %v", got)
	}
}

// TestRunPathsExtraEndToEnd extra 条目真实进入探测循环且去重：
// real 场景的 /actuator/heapdump 真实存在但不在内置 19 条字典里——
// extra 合并后应存活恰 1 条；内置条目（/robots.txt）照常生效。
func TestRunPathsExtraEndToEnd(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	out := t.TempDir()
	alive, err := RunPaths(srv.URL+"/real", out, "/actuator/heapdump", "/actuator/heapdump", "")
	if err != nil {
		t.Fatal(err)
	}
	countHeap := 0
	countRobots := 0
	for _, a := range alive {
		switch a.Path {
		case "/actuator/heapdump":
			countHeap++
		case "/robots.txt":
			countRobots++
		}
	}
	if countHeap != 1 {
		t.Errorf("extra /actuator/heapdump 应合并去重后存活 1 条, 得 %d（alive=%v）", countHeap, alive)
	}
	if countRobots != 1 {
		t.Errorf("内置字典 /robots.txt 应照常探测, 得 %d", countRobots)
	}
}
