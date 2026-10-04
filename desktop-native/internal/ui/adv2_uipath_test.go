package ui

// adv2_uipath_test.go — 原生轮第 2 轮对抗测试（零外网：只打白名单内 127.0.0.1 与假进程）。
// 覆盖三类此前未固化的攻击面：
//  1. 恶意目标走 UI 输入路径全矩阵——新建任务页「开始扫描」按钮的直接消费者
//     是 Session.CreateTask（app.go:247 用 targetEd.Text() 原样喂入），这里
//     按同类输入逐条打 CreateTask：file:// 内网地址 / 超长串 / 控制字符 / 非法域。
//  2. 可选参数毒数据走同一入口。
//  3. settings.json / tasks.json 毒数据（超长 / 类型错 / 路径穿越 / 坏结构）——
//     桌面端启动与证据导出必须优雅兜底，不得 panic、不得逃出 out/。

import (
	"path/filepath"
	"strings"
	"testing"

	"recon-native/internal/store"
)

// ── 1. 恶意目标 × UI 输入路径（CreateTask）──

func TestAdv2CreateTaskMaliciousTargets(t *testing.T) {
	s := newTestSession(t)
	long200 := strings.Repeat("a", 200)
	long201 := strings.Repeat("a", 201)
	reject := []struct {
		name, target, cmd string
	}{
		// file:// 内网地址（协议欺骗一类，全部拒绝）
		{"file 内网 DVWA", "file://192.168.88.130/dvwa", "paths"},
		{"file 本机 mock 端口", "file://127.0.0.1:8799/real", "api"},
		{"file 本地文件", "file:///C:/Windows/win.ini", "fingerprint"},
		{"file 管理共享", "file://localhost/c$/Windows", "jsintel"},
		{"smb UNC 路径", `\\192.168.88.130\dvwa`, "all"},
		// 超长串
		{"恰好 200 字符垃圾", long200, "all"},
		{"201 字符越界", long201, "all"},
		{"5000 字符洪水", strings.Repeat("xycovo.com.", 500), "subdomain"},
		{"白名单域名垫长到 200", "xycovo.com." + strings.Repeat("a", 189), "subdomain"},
		{"超长标签 64 字节", strings.Repeat("a", 64) + ".com", "subdomain"},
		// 控制字符 / 不可见字符
		{"NUL 内嵌", "xycovo\x00.com", "subdomain"},
		{"换行注入", "xycovo.com\nGET /admin HTTP/1.1", "all"},
		{"CRLF 头注入", "xycovo.com\r\nX-Injected: 1", "all"},
		{"TAB 分裂", "xycovo.com\t127.0.0.1", "all"},
		{"ESC 终端逃逸", "xycovo.com\x1b]0;pwn", "all"},
		{"DEL", "xycovo.com\x7f", "all"},
		{"垂直制表+换页内嵌", "xycovo.com\x0bevil\x0c", "all"},
		{"NBSP 内嵌", "xycovo\u00a0.com", "all"},
		{"零宽空格", "xycovo.com\u200b", "all"},
		{"RTLO 覆写", "xycovo\u202emoc.ovcy", "all"},
		// 非法域
		{"点开头", ".xycovo.com", "subdomain"},
		{"内嵌双点", "xycovo..com", "subdomain"},
		{"三点尾缀", "xycovo.com...", "subdomain"},
		{"标签首连字符", "-xycovo.com", "subdomain"},
		{"标签尾连字符", "xycovo.com-", "subdomain"},
		{"下划线标签", "xy_covo.com", "subdomain"},
		{"DNS 下划线记录名", "_dmarc.xycovo.com", "subdomain"},
		{"通配符域", "*.xycovo.com", "subdomain"},
		{"全角句号", "xycovo。com", "subdomain"},
		{"仿冒后缀", "xycovo.com.evil.com", "all"},
		{"仿冒前缀", "exycovo.com", "all"},
		// 环回 / 私网等价写法（归一化 key 不匹配名单即拒）
		{"环回缩写", "127.1", "portscan"},
		{"环回整数", "2130706433", "portscan"},
		{"环回八进制", "0177.0.0.1", "portscan"},
		{"环回十六进制+白名单端口", "0x7f.0.0.1:8799", "portscan"},
		{"mock 错端口", "127.0.0.1:8798", "api"},
		{"mock 端口补零", "127.0.0.1:08799", "api"},
		{"环回 IPv6", "[::1]:8799", "api"},
		{"裸 localhost", "localhost", "api"},
		{"userinfo 欺骗", "http://127.0.0.1:8799@xycovo.com/", "api"},
		{"反斜杠穿越", `xycovo.com\..\..\windows`, "all"},
		{"百分号编码穿越", "http://127.0.0.1:8799/%2e%2e/", "api"},
		{"明文穿越", "http://xycovo.com/../../win.ini", "api"},
		{"裸域带路径", "xycovo.com/admin", "all"},
		// 协议欺骗
		{"ftp 协议", "ftp://xycovo.com", "api"},
		{"gopher 协议", "gopher://xycovo.com", "fingerprint"},
		{"javascript 协议", "javascript:alert(1)", "api"},
		{"data 协议", "data:text/html;base64,QUFB", "paths"},
		// 模块形态错配
		{"subdomain 带 URL", "http://xycovo.com", "subdomain"},
		{"subdomain 带端口", "xycovo.com:443", "subdomain"},
		{"reverse 域名", "xycovo.com", "reverse"},
		{"all 带 URL", "http://xycovo.com", "all"},
		{"portscan 带 URL", "http://xycovo.com", "portscan"},
	}
	before := len(s.Store.List())
	for _, c := range reject {
		id, err := s.CreateTask(c.target, c.cmd, "")
		if err == nil {
			t.Fatalf("[%s] 应拒绝 %q（cmd=%s）", c.name, c.target, c.cmd)
		}
		if id != "" {
			t.Fatalf("[%s] 拒绝时不应返回任务 ID", c.name)
		}
	}
	if after := len(s.Store.List()); after != before {
		t.Fatalf("全部拒绝后任务库不应新增，before=%d after=%d", before, after)
	}
}

// TestAdv2CreateTaskAcceptMatrix 白名单内目标 × 各模块：应当入库并起扫描。
// 同时钉住归一化行为（含已知的双尾点等价放行——见对抗记录 INFO）。
func TestAdv2CreateTaskAcceptMatrix(t *testing.T) {
	s := newTestSession(t)
	accept := []struct {
		name, target, cmd, wantTarget string
	}{
		{"子域裸域名", "xycovo.com", "subdomain", "xycovo.com"},
		// 终修轮 P3 收口：入库/执行目标 = 白名单归一化 key——单尾点/双尾点
		// 等「等价写法」仍放行，但不再原样入参（对抗记录的「校验值≠执行值」
		// 卫生缺口已消除，wantTarget 由原始串改为归一形态）。
		{"子域单尾点", "xycovo.com.", "subdomain", "xycovo.com"},
		{"子域双尾点(白名单归一等价放行,入库为归一形态)", "xycovo.com..", "subdomain", "xycovo.com"},
		{"端口扫 IP", "47.100.49.228", "portscan", "47.100.49.228"},
		{"IP 反查", "47.100.49.228", "reverse", "47.100.49.228"},
		{"全模块域名", "xycovo.com", "all", "xycovo.com"},
		{"api 补协议", "127.0.0.1:8799", "api", "http://127.0.0.1:8799"},
		{"api 完整 URL", "http://127.0.0.1:8799/real", "paths", "http://127.0.0.1:8799/real"},
		{"指纹大写协议头", "HTTP://127.0.0.1:8799/real", "fingerprint", "HTTP://127.0.0.1:8799/real"},
		{"portscan host:port 白名单内", "127.0.0.1:8799", "portscan", "127.0.0.1:8799"},
		// 对抗记录 INFO：前/后置空白族（\v \f NBSP U+0085 等）被 CreateTask 的
		// TrimSpace 吞掉后放行，入库为裁剪后目标——与 whitelist「控制字符一律拒」
		// 的注释口径不一致；无越名单风险（归一结果仍是名单内主机），钉住现状。
		{"尾随 NBSP 被裁剪", "xycovo.com\u00a0", "subdomain", "xycovo.com"},
		{"尾随换页被裁剪", "xycovo.com\x0c", "subdomain", "xycovo.com"},
	}
	for _, c := range accept {
		id, err := s.CreateTask(c.target, c.cmd, "")
		if err != nil {
			t.Fatalf("[%s] 应放行 %q（cmd=%s）: %v", c.name, c.target, c.cmd, err)
		}
		got, ok := s.Store.Get(id)
		if !ok {
			t.Fatalf("[%s] 任务应入库", c.name)
		}
		if got.Target != c.wantTarget {
			t.Fatalf("[%s] 入库目标=%q, 期望 %q", c.name, got.Target, c.wantTarget)
		}
		if got.Status != store.StatusCreated && got.Status != store.StatusRunning {
			t.Fatalf("[%s] 新任务状态异常: %q", c.name, got.Status)
		}
	}
}

// ── 2. 可选参数毒数据 × UI 输入路径 ──

func TestAdv2CreateTaskArgsPoison(t *testing.T) {
	s := newTestSession(t)
	reject := []struct {
		name, args, cmd string
	}{
		{"argparse 缩写覆盖目标", "--ur http://10.0.0.5/x", "api"},
		{"缩写=形态", "--dom=evil.com", "subdomain"},
		{"短目标旗标", "-t 10.0.0.5", "portscan"},
		{"progress-file 劫持", "--progress-file=C:\\x\\evil.jsonl", "paths"},
		{"progress-file 下划线变体", "--progress_file C:\\x\\evil.jsonl", "paths"},
		{"帮助旗标", "-h", "all"},
		{"命令注入分号", "--ports 80;id", "portscan"},
		{"命令替换 $()", "--ports $(id)", "portscan"},
		{"反引号", "--ports `id`", "portscan"},
		{"管道符", "--ports 80|id", "portscan"},
		{"超 8 段", "--ports 1 --timeout 2 --workers 3 --max-files 4 --ports 5 --timeout 6 --workers 7 --max-files 8 --ports 9", "portscan"},
		{"单段超长", "--ports " + strings.Repeat("9", 250), "portscan"},
		{"大写旗标不在精确白名单", "--PORTS 80", "portscan"},
		{"取值位注入旗标", "--ports -u http://10.0.0.5", "portscan"},
		{"=值以 - 开头", "--ports=-1", "portscan"},
		{"跨模块旗标", "--verify", "jsintel"},
		{"all 无可选项", "--workers 4", "all"},
		// 终修轮 P4 收口：取值旗标挂尾（无值收尾）此前被 Go 层放行、到
		// Python argparse 才报 "expected one argument"——ValidateExtraArgs
		// 收尾 expectValue 即报错后，改在 Go 层拒绝。
		{"取值旗标挂尾", "--ports", "portscan"},
	}
	for _, c := range reject {
		if _, err := s.CreateTask("127.0.0.1:8799", c.cmd, c.args); err == nil {
			t.Fatalf("[%s] 参数 %q 应拒绝（cmd=%s）", c.name, c.args, c.cmd)
		}
	}
	// 放行组：白名单旗标原样入库
	ok := []struct {
		name, args, cmd string
	}{
		{"端口段", "--ports 1-1000 --timeout 3 --workers 50", "portscan"},
		{"等号取值", "--ports=80,443", "portscan"},
		{"jsintel 双旗标", "--max-files 20 --workers 4", "jsintel"},
		{"子域验证开关", "--verify", "subdomain"},
	}
	for _, c := range ok {
		target := "127.0.0.1:8799"
		if c.cmd == "subdomain" {
			target = "xycovo.com" // 子域模块只收裸域名（normalizeTarget 形态闸）
		}
		id, err := s.CreateTask(target, c.cmd, c.args)
		if err != nil {
			t.Fatalf("[%s] 参数 %q 应放行: %v", c.name, c.args, err)
		}
		if got, _ := s.Store.Get(id); got.Args != c.args {
			t.Fatalf("[%s] 入库参数=%q, 期望 %q", c.name, got.Args, c.args)
		}
	}
}

// ── 3. settings.json / tasks.json 毒数据 ──

func TestAdv2SettingsPoison(t *testing.T) {
	oneMB := strings.Repeat("C:", 1<<19) // ~1MB 字符串值
	poisons := []struct {
		name, body string
	}{
		{"类型错-数字", `{"python_path": 123}`},
		{"类型错-数组", `{"python_path": ["C:\\py\\python.exe"]}`},
		{"类型错-布尔", `{"python_path": true}`},
		{"类型错-对象", `{"python_path": {"path":"x"}}`},
		{"null 值", `{"python_path": null}`},
		{"未知字段+伪遥测端点", `{"python_path":"","admin":true,"telemetry_endpoint":"http://evil.example/collect"}`},
		{"BOM 前缀", "\xef\xbb\xbf{\"python_path\":\"C:\\\\py\\\\python.exe\"}"},
		{"尾随垃圾", `{"python_path":"x"} {"a":1}`},
		{"空对象", `{}`},
		{"纯 null", `null`},
		{"纯数字", `42`},
		{"顶层数组", `["x"]`},
		{"截断 JSON", `{"python_path": "C:\\py`},
		{"坏 UTF8", "{\xff\xfe\"python_path\"\xff:\"x\"}"},
		{"1MB 超长值", `{"python_path":"` + oneMB + `"}`},
		{"深嵌套 10 万层", strings.Repeat("[", 100000) + strings.Repeat("]", 100000)},
		{"路径穿越-相对", `{"python_path":"..\\..\\evil\\python.exe"}`},
		{"路径穿越-换盘", `{"python_path":"D:\\evil\\python.exe"}`},
		{"UNC 远端共享", `{"python_path":"\\\\attacker\\share\\python.exe"}`},
		{"带引号换行", "{\"python_path\":\"C:\\\"py\\n\\\\evil.exe\"}"},
	}
	for _, c := range poisons {
		dir := t.TempDir()
		if err := writeSettingsFile(dir, c.body); err != nil {
			t.Fatalf("[%s] %v", c.name, err)
		}
		st, err := LoadSettings(dir) // 任何毒数据都不得报错、不得 panic
		if err != nil {
			t.Fatalf("[%s] LoadSettings 不应报错: %v", c.name, err)
		}
		if strings.Contains(c.name, "UNC") {
			continue // UNC 值不再下探执行类调用：零外网纪律（执行面为已记账的 by-design 污点）
		}
		repo := t.TempDir()
		if err := makeStubRepo(repo); err != nil {
			t.Fatal(err)
		}
		sess, err := NewSession(repo, dir, `C:\fake\python.exe`) // 构造期不执行任何进程
		if err != nil {
			t.Fatalf("[%s] NewSession 不应失败: %v", c.name, err)
		}
		// 值没被毒坏的（类型错兜底零值）才做解析探针；探针只做 os.Stat，不执行
		if st.PythonPath == "" {
			if p, rerr := sess.Runner.ResolvePython(); rerr == nil && p == "" {
				t.Fatalf("[%s] 解析结果异常", c.name)
			}
		}
	}
}

// TestAdv2TasksPoison tasks.json 毒数据：开库兜底 + 恢复语义 + 导出不逃出 out/。
func TestAdv2TasksPoison(t *testing.T) {
	repo := t.TempDir()
	if err := makeStubRepo(repo); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	poisons := []struct {
		name, body string
	}{
		{"坏 JSON", `{{{`},
		{"顶层对象", `{"id":"x"}`},
		{"null 项", `[null]`},
		{"空 ID 项", `[{"id":"","status":"running"}]`},
		{"类型错字段", `[{"id":123,"status":["running"]}]`},
		{"BOM", "\xef\xbb\xbf[]"},
		{"截断", `[{"id":"x","stat`},
		{"穿越目标", `[{"id":"trav","status":"done","target":"..\\..\\Windows\\System32","cmd":"api"}]`},
		{"纯点目标", `[{"id":"dot","status":"done","target":"..","cmd":"api"}]`},
		{"盘符目标", `[{"id":"drive","status":"done","target":"C:\\Windows","cmd":"paths"}]`},
		{"设备名目标", `[{"id":"con","status":"done","target":"con","cmd":"paths"}]`},
		{"超长目标", `[{"id":"long","status":"done","target":"` + strings.Repeat("a", 200) + `","cmd":"paths"}]`},
	}
	for _, c := range poisons {
		tp := filepath.Join(dir, "tasks-poison.json")
		if err := writeFile(tp, c.body); err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(tp) // 毒文件必须兜底为可用库，不得让桌面端起不来
		if err != nil {
			t.Fatalf("[%s] Open 不应报错: %v", c.name, err)
		}
		if strings.Contains(c.name, "穿越") || strings.Contains(c.name, "盘符") ||
			strings.Contains(c.name, "设备名") || strings.Contains(c.name, "超长") ||
			strings.Contains(c.name, "纯点") {
			sess := &Session{Store: st, RepoRoot: repo, DataDir: dir}
			_, _, _, _, xerr := sess.ExportEvidence(taskIDOf(c.body))
			if xerr == nil {
				t.Fatalf("[%s] 毒目标导出应报错（无产物/非法目录），不得静默成功", c.name)
			}
		}
	}
}

// TestAdv2TasksPoisonBigArray 2 万条任务的毒库：开库与列表不得崩。
func TestAdv2TasksPoisonBigArray(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 20000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"t-` + itoa(i) + `","status":"done","target":"xycovo.com","cmd":"icp","created_at":1}`)
	}
	b.WriteString("]")
	tp := filepath.Join(t.TempDir(), "tasks.json")
	if err := writeFile(tp, b.String()); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(tp)
	if err != nil {
		t.Fatalf("大数组开库不应报错: %v", err)
	}
	if n := len(st.List()); n != 20000 {
		t.Fatalf("应恢复 2 万条，得 %d", n)
	}
}
