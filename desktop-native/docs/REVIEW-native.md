# desktop-native 冷复核报告（独立复核员·原生轮）

- 复核人：独立复核员-原生轮（未参与施工，冷复核）
- 日期：2026-10-05
- 对象：`C:/Users/18270/src-recon-tool/desktop-native/`
- 参照：验收指令 5 项 + `desktop-visual-acceptance` 清单 + 对照库 `desktop-go/internal/whitelist`
- 结论：**5 项核对全部通过**（其中视觉验收 4 个子项未跑/部分跑，见问题表）；发现 7 个 low/cosmetic 打磨项，无 high/medium。

---

## 1. 原生定位成立 ✅

**go.mod 无 wails/webview**（`desktop-native/go.mod` 全文）：

```
module recon-native
go 1.24.0
toolchain go1.24.1
require (
    gioui.org v0.10.3
    golang.org/x/sys v0.39.0
)
require (
    gioui.org/shader v1.0.9 // indirect
    github.com/go-text/typesetting v0.3.5 // indirect
    github.com/godbus/dbus/v5 v5.2.2 // indirect
    golang.org/x/exp/shiny v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
    golang.org/x/image v0.26.0 // indirect
    golang.org/x/net v0.48.0 // indirect
    golang.org/x/text v0.32.0 // indirect
)
```

- 直接依赖仅 `gioui.org`（纯 Go 即时模式自绘 UI）+ `golang.org/x/sys`（Win32 Job Object 用）。**无 wails、无 webview、无任何网页技术栈**。
- 工具链与零 CGO 证据（实跑）：

```
$ go version && go env GOOS GOARCH CGO_ENABLED
go version go1.24.1 windows/am64
windows
amd64
0
```

**真窗口证据**（实跑）：exe 起真 Win32 窗口，PowerShell `Get-Process` 取得实句柄与标题：

```
PID 100928 → HWND 984544 → TITLE 信息收集工具
SHOT shot-01-dashboard.png rect=(266,266)-(2058,1462) size=1792x1196   （150% 缩放，1180x760dp）
```

标题栏只有应用名 + 最小化/最大化/关闭，无地址栏/标签页残留（截图 shot-01～05、15 为证）。窗口、事件循环、自绘全部走 Gio（`main.go:18-27` 的 `app.Main()`，`internal/ui/app.go:137-165` 的 `app.Window` 事件循环）。

## 2. 产品名「信息收集工具」，「侦察工具」残留为零 ✅

- 窗口标题（代码 + 实跑双证）：`internal/ui/app.go:138` `w.Option(app.Title("信息收集工具"), ...)`；实跑 `TITLE 信息收集工具`（见上）。
- 全树 grep（实跑）：

```
$ grep -rn "侦察工具" C:/Users/18270/src-recon-tool/desktop-native
（零命中，exit=1）
```

- 更宽的 `grep -rn "侦察"` 全树仅 1 命中且为注释、且非「侦察工具」字样：`internal/ui/app.go:25` `// 五页信息架构（原「新建侦察」页定名「新建任务」）。`——改名历史的代码注释，不出现在任何界面文字。
- 界面文案核点：顶栏产品名 `app.go:428`、关于页 `page_settings.go:169`、退出报错 `main.go:21` 均为「信息收集工具」。五页截图（shot-01～05）肉眼复核无「侦察」字样。

## 3. 铁律 ✅

### 3.1 零 AI / 零对话组件

```
$ grep -rniE "chat|llm|gpt|openai|anthropic|对话|智能|助手|assistant|copilot|prompt|api[_ ]?key|embedding" internal/ main.go
internal/ui/page_settings.go:170:  "纯本地运行：零 AI 功能、无对话组件、不调用任何联网模型、不上报任何遥测数据。"
```

唯一命中是「关于」页的**自我声明文案本身**。无聊天 UI、无模型调用、无遥测代码。网络面实测：非测试代码里仅 `internal/ui/session.go:186-194` `mockReachable()` 一个 `http.Client.Get("http://127.0.0.1:8799/")`（白名单内本机靶站探测），无其他外联。

### 3.2 白名单闸未动（与 desktop-go 对照）

```
$ diff desktop-native/internal/whitelist/whitelist.go desktop-go/internal/whitelist/whitelist.go
29,33c29
< 	// 内嵌控制字符 / 非 ASCII 一律拒绝（URL 只认 ASCII 资产）。
< 	// 口径对齐（终修轮 P4）：壳层 CreateTask 会先 strings.TrimSpace（含
< 	// \v \f NBSP 等 Unicode 空白）再进本闸——首尾空白由壳的粘贴体验
< 	// 契约归一，归一后仍是名单内主机、无越闸面；本闸把守的是「内嵌
< 	// 控制字符」与「非 ASCII」，两层职责以本注释为界。
---
> 	// 控制字符 / 空白 / 非 ASCII 一律拒绝（URL 只认 ASCII 资产）

$ diff whitelist_test.go  → 完全一致（BYTE-IDENTICAL）
$ diff fix1_whitelist_test.go → 完全一致（BYTE-IDENTICAL）
```

**全部可执行代码逐字节相同**，唯一差异是 5 行 vs 1 行注释（native 版多出的是对 CreateTask 预裁剪契约的说明，`whitelist.go:29-33` vs `:25` 的 `strings.TrimSpace` 两边都在）。`Entries` 三条红线一致：`xycovo.com` / `47.100.49.228` / `127.0.0.1:8799`（`whitelist.go:14-18`）。

**真窗口行为验证**：名单外目标 `evil.example.com` 被拒，错误横幅「目标不在授权白名单，已拒绝（允许: xycovo.com / 47.100.49.228 / 127.0.0.1:8799）」（shot-06）；拼接串 `evil.example.com127.0.0.1:8799` 同样被拒（shot-07）。

### 3.3 应用层零 Python 运行时依赖（引擎子进程除外）

- `os/exec` 全树仅 `internal/engine/runner.go`：`python src/recon.py --progress-file ... <子命令>` 子进程（`runner.go:230-231`）与 `taskkill /T /F` 树杀（`:431`）。
- 应用层（main/ui/store/whitelist）无任何解释器嵌入、无 `python -c`、无 pip 依赖；`net/http` 仅 3.1 所述 mock 探测一处。
- UI 不依赖 Python 即可启动渲染：Python 仅在后台 goroutine 自检（`app.go:147-151`），找不到时界面照常出「未找到可用 Python」提示（shot-04 依赖卡、`page_settings.go:78-79`）。
- 引擎子进程随壳消亡：Windows Job Object `KILL_ON_JOB_CLOSE`（`job_windows.go:39`），壳被硬杀不留孤儿扫描。

## 4. go build + go test 重跑 ✅（本人实跑，非转述）

```
$ go build ./... && echo "=== GO BUILD EXIT 0 ==="
=== GO BUILD EXIT 0 ===

$ go test ./...
?   	recon-native	[no test files]
ok  	recon-native/internal/engine	19.722s
ok  	recon-native/internal/store	(cached)
ok  	recon-native/internal/ui	3.654s
ok  	recon-native/internal/whitelist	0.271s

$ go test -count=1 ./...          ← 强制全量非缓存
?   	recon-native	[no test files]
ok  	recon-native/internal/engine	26.229s
ok  	recon-native/internal/store	4.930s
ok  	recon-native/internal/ui	3.955s
ok  	recon-native/internal/whitelist	0.259s
```

4 个包全部 `ok`，零失败。另用 `go build -o recon-native.exe .` 重建了验收用 exe（18,066,944 字节，仅构建产物，未动任何源码）。

## 5. 真窗口视觉验收（desktop-visual-acceptance 清单走查）✅（含 4 个 not-run 子项）

方式：真起 exe（Gio 真窗口，非 headless），UIAutomation+SendInput 截图走查，验完 `WM_CLOSE`/`taskkill` 清零。截图 39 张留证于 `docs/review-native-shots/`（shot-01～18 编号，含脚本 stage1-9.ps1 可复跑）。

### A. 窗口层
| 项 | 结果 | 证据 |
|---|---|---|
| A1 标题栏=应用名、无浏览器残留 | ✅ | shot-01～05/15，`TITLE 信息收集工具` |
| A2 最小尺寸拖拽 | ⚠️ not run | 代码无 `app.MinSize`（仅固定初始 `app.Size(1180,760)`），脚本拖拽未执行 |
| A3 尺寸记忆 | ❌ 未实现 | 无 window.json 持久化；固定尺寸（low，见问题表 #4） |
| A4 DPI 双档 | ◐ 半跑 | 当前 150% 档全套走查无模糊/截断；100% 档未跑（改用户显示设置有侵入性，未执行） |
| A5 关窗确认 | ◐ 半验 | 任务已毕时 WM_CLOSE（与点 X 同消息路径 → DestroyEvent）直接退出、无孤儿进程 ✅；「任务运行中弹确认」未实现（`app.go:156-157` 直接 StopAll 退出，low，缓解：Job Object 树杀 `job_windows.go:39`） |
| A6 单实例 | ❌ 未实现 | 第二实例真实双开（pid 50632 独立 hwnd 920834，shot-14），low |

### B. 布局层
| 项 | 结果 | 证据 |
|---|---|---|
| B1 横向溢出 | ✅ 视觉级 | 五页走查无溢出/裁剪（Gio 自绘无 scrollWidth 可程序断言） |
| B2 命中测试 | ✅ | 侧栏五项真点击全部换页；模块 radio、开始扫描、导出、tab 全部实点生效 |
| B3 表格 | ◐ | 斑马纹/表头/分页条正常（shot-18）；100+ 行滚动压测未做 |
| B4 焦点环 | ◐ | 文本输入井焦点环清晰（shot-06）；Tab 到单选钮的焦点环不可辨（shot-13 vs 12），打磨项 |
| B5 分段截图 | ✅ | 39 PNG，150% 一套；100% 未拍（随 A4） |

### C. 键盘与状态
| 项 | 结果 | 证据 |
|---|---|---|
| C1 键盘 | ◐ | Ctrl+2/Ctrl+3/Ctrl+5 实证换页（shot-11/12/16）✅；Tab 遍历到部件层 ✅；Esc 停止任务未逢时机未实测 |
| C2 三态 | ✅ | 空态（shot-01/03）、错误态（shot-06 白名单拒绝）、运行态（shot-09-running，过程流实时刷新）、成功态（shot-15「任务已开始」横幅）各真实出现 |
| C3 reduced-motion | N/A | 应用无动画元素 |
| C4 主题对比度 | ✅ 视觉级 | 深色主题 token 统一，正文对比度目测达标 |

### D. 数据真实性 ✅（本轮最有分量的证据）
一条**经真窗口 UI 发起的全流水线任务**（xycovo.com / 全部模块）从列表→选中（▶ 选中）→详情（开始 02:44:45 / 结束 02:47:12 / **退出码 0 / 已完成**）→22 条过程记录（流水线→子域枚举→verify→asset→ICP 备案→指纹识别→…→report→pipeline_end done）→**导出证据包成功**：

```
EVIDENCE C:\Users\18270\AppData\Local\recon-native\evidence\20261005-024445-b8dbb647.zip 6998bytes
回执：「已导出 ...20261005-024445-b8dbb647.zip（现打聚合包）：打包 13 条，跳过 0 条」  （shot-18）
```

历史任务重开 ✅（重启应用后任务仍在，shot-16）；结果页无「删除任务」功能（#5）。断点续传（任务运行中重开会话恢复）未实测——engine 层 `ErrNotRunning` 幂等有单测覆盖，UI 层未走查。

### E. 证据与判级
39 PNG + 本问题表。无 high、无 medium；7 个 low/cosmetic 打磨项不构成交付阻塞。

---

## 问题表（severity / where / what / 证据）

| # | 级别 | 位置 | 问题 | 证据 |
|---|---|---|---|---|
| 1 | low | `internal/ui/page_results.go:174` + `app.go:168-183` | 结果页首次进入分页显示「第 0 / 1 页」：`a.listPage` 初值 0，`PageBounds` 内部钳位到 1 但显示层打印原始值 | shot-16/18 |
| 2 | low | `main.go`（无单实例逻辑） | 双实例可双开，checklist A6 期望唤起/退出 | shot-14（pid 50632+103276 并存） |
| 3 | low | `internal/ui/app.go:156-157` | 任务运行中点 X 无确认弹窗，直接退出；缓解：Job Object 树杀不留孤儿 | 代码 + A5 走查 |
| 4 | low | `app.go:138` | 无尺寸记忆（固定 1180x760，无 window.json） | checklist A3 |
| 5 | low | 结果页 | 无「删除任务」入口（checklist D2 的删除项） | shot-16/18 |
| 6 | cosmetic | 结果页 tab 行 | 「全部」（筛选 tab）与「全部模块」（模块名）并存，初见易混淆 | shot-03 |
| 7 | 打磨 | 单选钮/按钮 | Tab 焦点环在单选钮上不可辨（输入井已修复，其余部件未带可视环） | shot-13 vs shot-12 |
| 8 | 观察（推断） | `page_dashboard.go:88-92,140-146` | 150% 下统计卡折两行 2+2，而主区 908dp > 756dp 本可一行四卡；推断成因：`gtx.Dp(1)` 在 1.5 倍取整为 2，`statCols(Max.X/pxPerDp)` 低估可用宽（681<756）。视觉尚可，不影响使用 | shot-01 |

## 未跑清单（如实声明）

- A2 最小尺寸拖拽、A4 的 100% DPI 档、B3 的 100+ 行滚动压测、C1 的 Esc 停止任务实测、D3 断点续传 UI 走查——均未执行，原因：涉及改用户显示设置或缺少可安全中断的运行中任务时机；均不掩盖为通过项。
- 导出功能的逻辑层正确性由 `internal/ui` 包测试（`evidence_test.go` 等，见第 4 节全绿）与真窗口导出成功（shot-18 + zip 落盘 6998B）双证。

## 环境事项（影响走查过程，如实记录）

本机桌面在复核期间有**真人同时使用**（正开着孵化本复核的智能体工作流控制台）：造成 stage3 脚本点击落偏、窗口被移动/最小化（ClientToScreen 返回 -32000 系最小化坐标）、以及上述由真人经 UI 发起的 xycovo.com 任务——该任务反而成为 D1 的真实全链路证据。stage9 起自动化加入前台校验（`GetForegroundWindow()==目标 HWND` 才点击）后全部落点正确。X 按钮的合成点击两次未生效（疑似与真人鼠标竞争），改用等价消息路径 `WM_CLOSE` 验证关窗成功。

## 清理核验（验收后实跑）

```
tasklist | grep -i recon-native   → 零残留（exit=1）
netstat -ano | grep ":8799"       → mock 靶站已停，端口释放（exit=1）
```

## 最终判定

- 核对 1（原生定位）：**PASS**
- 核对 2（产品名归一）：**PASS**
- 核对 3（三铁律）：**PASS**
- 核对 4（build+test）：**PASS**（4 包全 ok，含 -count=1 全量）
- 核对 5（真窗口视觉验收）：**PASS（带 7 个 low/cosmetic 打磨项 + 5 个如实声明的未跑子项；无 high/medium）**

**视觉验收判级：PASS，允许交付。**
