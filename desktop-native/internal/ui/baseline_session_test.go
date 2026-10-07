package ui

// baseline_session_test.go — 基线模块的会话层接线：
//   - normalizeTarget baseline 分支 = 域名形态（拒绝协议/端口，同 subdomain/icp）；
//   - CreateTask("target","baseline",args) 走既有校验链入库并进程内直调
//     （recon-go.exe 第二子进程已随第 2 步退役，SetGoEnginePath/SetPythonPath
//     与 settings 双字段持久化用例一并移除）。

import "testing"

func TestCreateTaskBaselineDomainShape(t *testing.T) {
	s := newTestSession(t)

	// 域名形态放行；可选参数只认 --checks
	id, err := s.CreateTask("xycovo.com", "baseline", "--checks secheaders,webfiles")
	if err != nil {
		t.Fatalf("baseline 域名目标应放行: %v", err)
	}
	got, ok := s.Store.Get(id)
	if !ok {
		t.Fatal("任务应入库")
	}
	if got.Target != "xycovo.com" || got.Cmd != "baseline" || got.Args != "--checks secheaders,webfiles" {
		t.Fatalf("入库不符: %+v", got)
	}

	// 拒绝：协议 / 端口（域名形态闸，同 subdomain/icp）/ 目标旗标夹带
	for _, c := range []struct{ target, args string }{
		{"http://xycovo.com", ""},
		{"xycovo.com:443", ""},
		{"xycovo.com/admin", ""},
		{"127.0.0.1:8799", ""},
		{"xycovo.com", "-d evil.com"},
		{"xycovo.com", "--checks -u"},
		{"xycovo.com", "--verify"},
	} {
		if _, err := s.CreateTask(c.target, "baseline", c.args); err == nil {
			t.Fatalf("baseline 目标 %q args %q 应拒绝", c.target, c.args)
		}
	}
}
