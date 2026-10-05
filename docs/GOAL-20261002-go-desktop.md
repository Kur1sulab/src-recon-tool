# GOAL 日志 — src-recon-tool Go 桌面版

> 项目：src-recon-tool 桌面化（desktop-go/）｜远端真相源：`git@github.com:Kur1sulab/src-recon-tool.git`
> 本文档为迭代日志，每轮收尾由架构师追加。另：`pentest/vulnscan-platform/docs/` 下有同名文件属**另一项目**（Wails 壳），勿混淆（REVIEW-c1 §6-P1）。

---

## 第 1 轮（骨架轮 / C1）总结 — 2026-10-02

### 目标

按第 1 轮方向：git fetch 对齐远端 → 从零建 `desktop-go/`（go.mod + internal/server 六接口 + internal/engine recon.py 子进程管理 + desktop 壳 + frontend 五页面板接真 API），引擎进度机制按设计定案落地；验收 = `go build` 单 exe + `go test` 全绿 + mock 靶站端到端（模块进度/结果表格/证据包导出按钮在位）+ 零对话组件。

架构师设计期三项定案（C1 IterPlan，已交施工）：

1. **壳选型 jchv/go-webview2**（弃 Wails v2）：免 CGO、依赖树最小、`go build` 一把出单 exe；架构 = 同进程 `127.0.0.1` 随机端口 HTTP server（embed 前端 + 六接口），壳 Navigate 该地址；`--dev` 旗标不起壳只起服务供浏览器联调。
2. **进度机制定案 `--progress-file` JSONL**（弃 stdout 解析）：recon.py 原有输出仅 `print("[*]/[+]/[!]")` 无模块边界事件（src/recon.py:66-212 通读），正则猜边界脆弱且踩 Windows 中文编码坑；JSONL 增量落盘支持 UI 轮询 tail、进程崩溃进度不丢；Python 侧最小改动全在 recon.py 内。
3. **白名单=正点名单**：`{xycovo.com, 47.100.49.228, 127.0.0.1:8799(mock)}` 名单外一律拒绝——mock 靶站是用户红线明示授权项，正点名单比"拒环回/私网"黑名单更严，平台级约束的冲突按此处置。

### 产出

**git（本轮实跑 `git log --oneline -8` / `git remote -v`）**：

- origin 已 set-url 至 SSH 真相源：`git@github.com:Kur1sulab/src-recon-tool.git` ✅（C1 计划第①步兑现；计划前状态为误指 xiaoyang-xyc 旧地址）
- 新 commit 链（自旧到新）：
  - `c5a131c` engine(progress): recon.py --progress-file JSONL 落盘+单测（`src/recon.py:175` argparse 参数 + `:34-60` `_emit` + `tests/test_progress_file.py`，独立提交）
  - `2726c7a` / `88373cc` / `3c76fa0` / `c76962d` **engine-go(c1) 系列**：Go 引擎底座（netutil/jsonx 含 SSRF 边界与安全落盘）、mockweb httptest 靶站（与 mock_server.py 逐字节对齐+漂移守卫）+ toolrun 子进程适配、subdomain/fingerprint 28 规则 + 14 子命令 CLI + Python↔Go parity 矩阵、CLI 布局重构。——超出 C1 架构师草案的额外 track：desktop 壳本身仍按铁律以子进程调 Python 引擎（REVIEW-c1 §1.5 证实 runner.go:188 argv 注入 `--progress-file`），engine-go 为并行 Go 引擎工程（关系待第 2 轮明确，见遗留 7）
  - `afcbf98` desktop-go(r1): 桌面壳入库 + 第 1 轮审计/对抗修复

**desktop-go/ 结构（本轮 `ls -R` 实测）**：

- `go.mod`：module recon-desktop，唯一直接依赖 `github.com/jchv/go-webview2`（indirect 仅 go-winloader、x/sys；go.mod:1-10）
- `main.go`：壳 + `//go:embed frontend`（main.go:37，无 `all:` 前缀——`.mimosa` 等隐藏产物不进 exe）+ 只绑回环（main.go:79）+ 退出顺序（停服务→StopAll 杀扫描进程树→存窗口尺寸，main.go:94-99,156-161）
- `desktop.go`：窗口尺寸记忆（window.json clamp 960x640~7680x4320）、单实例命名互斥、原生 MessageBox
- `internal/{server,engine,store,whitelist}` + 各 fix 测试；`frontend/`（index.html + css×2 + js×6 + DESIGN.md，原生三件套零构建链）
- `recon-desktop.exe` 11,128,320 字节在位（本轮 `ls -la` 实测）；`docs/REVIEW-c1.md` 独立冷复核报告

**六接口与五页（与草案字面有命名偏差，偏差登记不判缺陷，REVIEW-c1 §1.7/§1.8）**：

- 六接口（server.go:52-59）：`GET /api/env`、`POST /api/scans`、`GET /api/scans`、`GET /api/scans/{id}`、`POST /api/scans/{id}/stop`、`GET /api/scans/{id}/evidence`
- 五页（hash 路由，接真 API）：任务列表（800ms 轮询）/ 新建侦察（POST scans + env 白名单下发）/ 任务详情（进度事件+产物表+日志尾，终态自停轮询）/ 证据包（Blob 下载）/ 设置（自检+白名单只读）

**mock 靶站端到端（REVIEW-c1 §1.9 复核员活体复现，零外网）**：`python tests/mock_server.py 8799` + 自建 exe `--dev --port 8791` → POST api 任务 6s done、progress 4 事件（JSONL 经 Tailer 进库）、artifacts 16 项、evidence zip 11,553B（testzip=None、无穿越条目）。

### 审计对抗处置

- **白名单闸纵深**：whitelist.go:14-101 三条目深校验（控制字符/非 ASCII/`%2e/%2f/%25` 编码绕过/userinfo/环回仅 8799 端口/域名格式）；服务端名单外 403（server.go:214-217）；args 目标旗标黑名单（server.go:178-181）+ `--progress-file` 前缀拦截（server.go:310-313，含 `--progress_file=` 下划线等号形式）+ `ValidateExtraArgs` 按模块精确旗标白名单堵 argparse 前缀缩写（fix1_extra.go:42-72）。
- **14/14 对抗项活体复现全过，未发现回退或假修复**（REVIEW-c1 §3 表）：名单外 403、私网端口漂移 403、args 藏目标 400、缩写绕过 400、progress-file 劫持 400×2、取值旗标藏目标 400、弃用子命令 llm 400、Host 伪造（DNS rebinding）403、跨站 Origin 403、自身 Origin 不误伤 200、穿越读文件 404、隐藏目录泄露 404、方法不匹配 405+Allow。
- **传输与存储**：localGuard（Host 白名单+Origin 同源，server.go:72-92）、body 8KB 封顶、全响应 no-store、outDirFor 清洗 `..`/Windows 保留字符必落 out/ 内（server.go:377-390）、证据包超限文件整只跳过留痕（server.go:519-544）、现成 zip 条目审计 evidenceZipSafe（server.go:555-587）、崩溃恢复 running→fail 对账（store.go:84-94）。
- **前端 XSS 面为零**：App.h 构建器动态数据一律 textContent，`innerHTML|insertAdjacentHTML|document.write` grep 0 命中；CSP `script-src 'self'; style-src 'self'`，内联样式 0 命中（REVIEW-c1 §1.6/§2）。
- **子进程纪律**：列表 argv 无 shell、`PYTHONUTF8=1`+`PYTHONIOENCODING=utf-8` 注入（runner.go:191）、stdout/stderr 原样落 logs/ 不解析、树杀 `taskkill /T /F` 失败回退 Kill 且幂等（runner.go:334-353）。
- **零对话组件铁律**：`grep -rniE "聊天|气泡|对话|发送按钮|计划卡|chat|bubble|assistant"` 与 `\bAI\b|智能体|agent|llm` 对 frontend/ 均 0 命中；交互全为表单/表格/按钮/下拉（REVIEW-c1 §2）。

### 美术要点

- 视觉体系 **"Slate Sonar"**（frontend/DESIGN.md，staged 未提交）：深色控制室——冷蓝石板底（canvas `#0c1116` / chrome `#101820`）、**青鹤唯一强调**（primary `#3cb8a8`、accent-hi `#74d6c7`）、状态三色各 tri-tone token（ok/warn/bad 底线底三档）、圆形声呐 LED、等宽数据列、斑马纹数据行；正文 13px system-ui/'Microsoft YaHei UI' 栈、行高 1.55。
- 纯 CSS token 化落地：css/tokens.css（新增 87 行）+ app.css 重绘（±520 行）；无构建链、无内联样式（CSP 不放宽）。
- 可用性实测（REVIEW-c1 §5）：对比度 WCAG 相对亮度公式实算全部 ≥4.5:1（tx-1/s2=13.22:1、tx-2/s2=7.07:1、acc-ink/acc=7.02:1）；`:focus-visible` 2px 品牌青描边；`prefers-reduced-motion` 全局动画压制；≤760px 断点 + `.table-wrap overflow-x:auto` 溢出防线。
- 交互键位：Ctrl+1..5 切页、Esc 停运行中任务、离线横幅+状态灯；空/错/载三态齐备（tasks.js:56-59、index.html:68-70 等）。

### 复核结论

- **独立冷复核**（REVIEW-c1.md，2026-10-02 06:13–06:40，复核员未参与施工）：**第 1 轮验收目标达成（代码与 API 层）**。计划逐条兑现（2 处命名偏差登记）；四条铁律读码+grep+实跑证实；复核员亲跑 `go build` 单 exe（11,188,736B，CGO_ENABLED=0）与 `go test -count=1 ./...` 四包全绿（48 个测试函数）；14/14 对抗活体全过；`go vet`/`gofmt`/`node --check` 干净。**视觉验收未跑真窗口，按指令以代码走查替代，不打「视觉验收 PASS」**（§5，A/B 层留第 2 轮）。
- **架构师追加复核（本轮，2026-10-02）**——以下为本 session 实跑：
  - `go test -count=1 ./...`（desktop-go/，工作树=afcbf98+5 个 staged 件）→ engine 2.962s / server 3.565s / store 8.161s / whitelist 0.220s **四包 ok 全绿** ✅
  - `ls -la recon-desktop.exe` → 11,128,320 字节在位 ✅
  - `git remote -v` → origin=Kur1sulab（SSH）✅；`git status -sb` → `main...origin/main [ahead 1]`（afcbf98 未推送，见遗留 2）；`git status --porcelain` → 5 个 staged 未提交件
  - `ls docs/` → 本 GOAL 文档此前不存在（仅 audit-20260924.md）→ 本条目即 REVIEW-c1 §6-P1 的收口动作
- 本轮**未跑**（如实登记）：真窗口视觉走查与分段截图、`-race`（本机 CGO_ENABLED=0 无 gcc）。

### 遗留（转第 2 轮）

1. **P2 收口**：美术轮 5 文件 staged 未 commit——`frontend/DESIGN.md`、`frontend/css/tokens.css`、`frontend/css/app.css`、`desktop-go/README.md`、`internal/whitelist/fix1_whitelist_test.go`（白名单模糊表 90+ 用例回归）。第 2 轮开工先 commit（铁律 5 每轮收尾）。
2. **push 未完成**：`main` 领先 `origin/main` 1 个 commit（afcbf98；基于本地引用，本轮未 fetch 网络核实远端实态）。第 2 轮收尾随新 commit 一并走 SSH over Clash 隧道推送，失败重试 ≤3。
3. **真窗视觉验收**：SKILL desktop-visual-acceptance A/B 层（真窗口走查+分段截图）未跑——第 2 轮既定范围。
4. **P4**：A2 实时最小尺寸未约束（尺寸 clamp 仅作用于记忆值，WebView2 选项缺 MinWidth/MinHeight，运行中可拖更小）；A4 DPI（PerMonitorV2 manifest）未验。
5. **P3**：desktop.go:4 注释称「非 Windows 回退 --dev」，但 syscall.NewLazyDLL 为 Windows 专属，注释与实现不符——建议改注释（Windows-only 为实际范围）。
6. 前端 ↑ 回填输入历史缺失（§5 C1）；任务重开/删除未实现（第 2 轮草案范围，§5 D2）。
7. 未实测项：证据包 >64MB 单文件跳过路径、崩溃重启对账（均仅单测覆盖）。
8. **engine-go track 定位**：desktop 壳当前只调 Python 流水线（铁律 2 口径），engine-go 为并行 Go 引擎工程（parity 矩阵+mockweb 漂移守卫）——其与桌面壳的接入或归档关系需第 2 轮明确决策，避免双引擎叙事混乱。

---

## 原生转向与两轮施工总结（native 线收口）— 2026-10-05

### 用户裁定：转向原生

webview 线（desktop-go/）走到美术方案 C 双主题提案（`a3a3c0c`，10-04 14:17）后，用户裁定桌面壳改走**纯 Go 原生自绘**路线：零 CGO、零网页技术栈、零 WebView2 运行时依赖；**webview 版 desktop-go/ 不删除，保留为参考实现**；产品定名维持「信息收集工具」。裁定后 2 小时尖峰、4 小时骨架轮入库。时间线（本轮 `git log --format='%h %ad %s'` 实查）：

`a3a3c0c`（14:17，webview 线末笔）→ `373e57c` skeleton（16:20）→ `f0a08f0` full（19:23）→ `c3cfc27` fix1（22:18）→ `65d4ee2` / `9370d00` final（10-05 00:35 / 02:22）。

### 选型证据与尖峰

- **选型 gioui.org v0.10.3**：直接依赖仅 Gio（纯 Go 即时模式自绘 UI）+ golang.org/x/sys（Win32 Job Object 用），desktop-native/go.mod 全文无 wails/webview/网页栈（REVIEW-native.md §1 实读）；`go env` 实测 GOOS=windows、CGO_ENABLED=0、go1.24.1。相对 webview 壳的实质变化：UI 渲染完全在应用进程内，不再依赖系统 WebView2 Runtime。
- **尖峰（desktop-native/spike/，随骨架轮 373e57c 入库）**：最小窗口=一个按钮+一张三行表格（spike/main.go），验证三件事——① Gio 在 Windows 纯 Go 下 build 出 exe 且能起真窗口；② 中文渲染注册 `msyh.ttc`（TTC）可行，spike/run.log 实跑留痕 `FONT: msyh.ttc ok, faces = 2`（后成为生产 loadFaces 的字体路径，DESIGN-native.md §字体行）；③ 两种构建产物在位：spike-gio.exe / spike-gio-nocgo.exe 各 11,241,984 字节（本轮 `ls -la` 实测，10-04 14:52/14:53）。
- 如实登记：仓内没有候选框架逐项对比矩阵文档；「原生」路线本身是用户裁定（本轮验收指令明示），仓内证据是尖峰可行性实跑 + go.mod 依赖面 + 复核 §1 证实。

### 骨架轮（`373e57c`，10-04 16:20）

- 模块 `recon-native`；whitelist/store/engine 三包自 desktop-go 拷贝，go test 证等价；32 文件 +4145 行（`git show --stat` 实查）。
- 五页导航骨架：仪表盘/新建任务/结果/工具/设置（页面命名按定名令即「新建任务」，无「新建侦察」）；「石板声呐」深色令牌进 theme.go Go 常量。
- 新建任务页接线引擎子进程管理全链（白名单闸→目标归一→参数白名单→入库→起 recon.py），TDD 红绿；mock 靶站端到端测试（真引擎跑通结果表格出条目，无靶站自动跳过）。

### 全功能轮（`f0a08f0`，10-04 19:23）

- 结果页：模块 tab 胶囊 + 双表 50 行分页 + 证据包导出（现成 zip 审计复用/现打聚合包、嵌套 zip 与超限留痕——规则自 desktop-go server.go **同语义移植**；evidence.go 新件 + evidence_test.go 183 行）。
- 设置页 settings.json 持久化（解释器路径 保存>env 优先级、重启生效）+ 输出目录只读卡；工具页外部依赖状态卡（Python/引擎脚本/mock 靶站/out 目录，LED 点三色）。
- 键盘流 Esc 停止 + Ctrl+1..5 切页（Tab 遍历走 Gio FocusFilter 内建）；空/载/错三态补全；-lo 纪律修复（停止钮底改 err-bg）；docs/DESIGN-native.md 令牌对照表+五页视觉要点+四条硬边界（Tx3 禁上 S4、Idle 不作文字色等）；TDD 红绿 14 新测试；12 文件 +1228/−22。

### 真窗口验收与 fix1 轮（`c3cfc27`，10-04 22:18）

- 验收方式（REVIEW-native.md §5）：真起 exe（Gio 真窗口，非 headless），UIAutomation+SendInput 走查，39 张截图留证 docs/review-native-shots/（shot-01～18 + stage1-9.ps1 可复跑）。A 层标题栏只有应用名无浏览器残留、关窗不留孤儿；B 层五页无溢出、命中测试全过；C 层 Ctrl+2/3/5 实证换页、三态齐备；**D 层最有分量——一条经真窗口 UI 发起的全流水线任务**（xycovo.com/全部模块，退出码 0，22 条过程记录，证据包 zip 6998 字节导出成功，shot-18 回执）。
- 验收揪出 9 项 high/medium，fix1 轮全落：共同根因是 gioui.org v0.10.3 `layout/stack.go` 的 Stack 铺底语义（Stacked 的 Min 清零、Expanded 只抬到内容自然尺寸）——theme.go card 底钉 Max.X + 新增 cardFill 满槽位铺底，真窗口像素探针五页 WHITE 采样 **63866→0**；monoLabel 加 isASCII 守卫（Consolas 无中文字形，验收 8 处丢字的根因）；工具页包垂直 List 滚动；快捷键过滤器加 Optional 修饰键（Alt/AltGr 卡死免疫）；输入井 2dp 品牌青焦点环。Ctrl+2 首按 3/3 重启复验通过。

### 审计对抗处置（final 轮，`65d4ee2` + `9370d00`）

- **台账（desktop-native/docs/SECURITY-ADVISORIES.md，已入库）**：
  - ADV-20261004-01 `RECON_PYTHON` 跨文件污点（medium，by-design 人工背书，2026-10-04 修复会话用户确认；升级条件写明：出现「远端可写配置源」通道即须在 SetPythonPath 加路径校验并重评）。
  - ADV-20261004-02 壳被硬杀→扫描进程孤儿（对抗实验实锤：taskkill /F 硬杀父进程后 PING.EXE 存活）→ **Job Object 根治**：runner.Start 起进程即挂 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`（job_windows.go:39），壳优雅退出或被硬杀，句柄随进程回收关闭、Job 内整树同步终局；killTree 保留兜底，非 Windows 走 job_other.go 空实现。回归 job_windows_test.go：真 cmd→ping 树挂 Job，关句柄后 tasklist 全局 PING.EXE 归零。
- **纵深与收口**：引擎层纵深闸（runner.Start 复检 whitelist.Check + taskIDRe 校验 id——闸外新调用方直连 Start 也绕不过）；白名单归一化 key（**校验值=执行值**，双尾点等价写法不再原样进 argv；normalizeTarget 两段式，url 保留 scheme/路径尾巴）；fix1_extra.ValidateExtraArgs 取值旗标挂尾 Go 层收闸；ProbePython 10s 超时树杀（解释器挂起不再冻死事件循环）；自检 goroutine 数据竞争消除；统计卡窄主区折两行。
- **对抗测试**：adv2 三件（adv2_uipath / adv2_helpers / adv2_concurrency）——放行矩阵 wantTarget 改钉归一形态、取值旗标挂尾行由放行矩阵迁入拒绝矩阵（「校验值≠执行值」缺口消除）。
- 纪律：两笔提交均经用户常设授权 `--no-verify` 降级（Mimosa 复扫命中的 medium 均属已台账背书 advisory 家族，行零改动），pathspec 仅 desktop-native。

### 复核结论

- **独立冷复核**（desktop-native/docs/REVIEW-native.md，独立复核员未参与施工，2026-10-05）：**5 项核对全部 PASS**——①原生定位（go.mod 无 wails/webview、CGO_ENABLED=0、真 Win32 窗口 PID/HWND/TITLE 实取 `信息收集工具`）；②产品名（窗口标题 app.go:138 / 关于页 page_settings.go:169 / main.go:21 三处代码+实跑双证，`grep -rn "侦察工具"` 全树零命中）；③三铁律（零 AI/对话/遥测——grep 唯一命中是关于页自我声明文案本身；白名单闸与 desktop-go 对照可执行代码逐字节相同、仅注释差 5 行 vs 1 行，三条红线一致 whitelist.go:14-18；应用层零 Python 运行时依赖，引擎仅 runner.go 子进程）；④build+test（复核员亲跑 `go build` + `go test -count=1` 四包全绿）；⑤真窗口视觉验收 **PASS**——7 个 low/cosmetic 打磨项 + 5 个如实声明的未跑子项，**无 high/medium，允许交付**。
- **架构师追加复核（本轮，2026-10-05 实跑）**：
  - `C:/Go/go/bin/go.exe build ./...`（desktop-native/）exit 0；`go test -count=1 ./...` → engine 25.185s / store 6.631s / ui 6.160s / whitelist 0.211s **四包 ok 全绿** ✅
  - `ls -la recon-native.exe` → 18,066,944 字节在位（02:32 复核员重建产物）✅
  - `grep -rn "侦察工具" desktop-native --include=*.go --include=*.md` → 仅 REVIEW-native.md 引文自命中，代码/UI 零命中 ✅
  - `diff` whitelist.go（native vs desktop-go）→ 仅注释差异（归一口径说明），与复核 §3.2 一致 ✅；`git ls-files desktop-native/docs/` → DESIGN-native.md 与 SECURITY-ADVISORIES.md 已入库 ✅
  - `git status -sb` → `main...origin/main` 无 ahead/behind 标记（基于本地引用，本轮未 fetch 网络核实远端实态）

### 遗留

1. **复核件未入库**：desktop-native/docs/REVIEW-native.md + docs/review-native-shots/（39 PNG + stage1-9.ps1）仍 untracked——下轮开工先以仅带 desktop-native 的 pathspec commit（铁律 5 每轮收尾）。
2. REVIEW-native 问题表 7 项 low/cosmetic：结果页首进「第 0/1 页」显示（page_results.go:174 + app.go:168-183）；无单实例互斥（真双开实证 shot-14）；任务运行中点 X 无确认弹窗（app.go:156-157 直接 StopAll，Job Object 树杀缓解）；无窗口尺寸记忆（固定 1180x760）；结果页无「删除任务」入口；「全部/全部模块」并存易混；单选钮 Tab 焦点环不可辨。
3. **未跑清单（如实声明，非通过项）**：A2 最小尺寸拖拽、A4 的 100% DPI 档、B3 100+ 行滚动压测、C1 Esc 停止实测、D3 断点续传 UI 走查；`go test -race` 本机无 cgo/gcc 不可跑（65d4ee2 提交信息已建议 CI 补跑）。
4. webview 版 desktop-go/ 按裁定保留为**参考实现**：其工作树现有在途未提交改动（frontend 10 件 M + assets/、docs/design-proposals/、internal/ico/、tools/ 等 untracked）属其他线，遵提交纪律不动、不提交、不带 pathspec。
5. 主题融合裁定：深色「石板声呐」唯一规范主题，浅色/双主题机制缓议另立项（DESIGN-native.md 头注）。本册 webview 线的 c2/美术轮未另立 GOAL 节（收口见提交 `4853fc5` / `7aa31bd` / `d1f6fc8` / `a3a3c0c` 与 REVIEW-c1），原生线起以本节为准续追。

---
*后续轮次按此格式续追。*
