# REVIEW-c1 — desktop-go 第 1 轮（骨架轮）独立冷复核

- 复核员：独立复核员-1（未参与施工，冷读）
- 复核时点：2026-10-02 06:13–06:40（文件 mtime 口径：所读源码均早于复核开始）
- 复核对象：`C:/Users/18270/src-recon-tool/desktop-go/`（HEAD=afcbf98 + 5 个 staged 未提交文件，见 §6）
- 计划正本：`C:/Users/18270/.zcode/workflow-drafts/侦察工具Go桌面版goal.dwf.ts`（cycleHints[0] 与铁律全文）。
  ⚠️ 交付指令所给计划路径 `src-recon-tool/docs/GOAL-20261002-go-desktop.md` **复核时点不存在**（见 §6-P1）；
  同名文件 `pentest/vulnscan-platform/docs/GOAL-20261002-go-desktop.md` 属另一项目（zcode-app-go/Wails），与本轮无关，未作为依据。
- 零污染声明：复核全程未改任何生产代码。写入仅限：本文档、`%TEMP%` 下的复核用 exe/zip/日志、隔离数据目录 `%TEMP%/recon-review-data`（未用真实 %LOCALAPPDATA%）；端到端扫描产物落在仓库 `out/`（gitignored 运行时目录）。测试服务已全部停止（netstat 复核 8791/8799 零 LISTEN）。

---

## 总判

**第 1 轮验收目标达成（代码与 API 层）**：计划承诺逐条兑现（含 2 处与草案字面不同但语义等价的偏差，见 §1.7/§1.8）；四条铁律全部读码+grep+实跑证实；14 项对抗抽查零外网活体复现全部成立；`go build` 单 exe 与 `go test -count=1` 四包全绿为复核员亲跑。**视觉验收未跑真窗口，按指令以代码走查替代（§5），不打「视觉验收 PASS」。**

---

## 1. 计划兑现 — 逐条验证

计划原文（cycleHints[0]）：「git fetch 对齐→建 desktop-go/（go.mod+internal/server 六接口+internal/engine recon.py 子进程管理+desktop 壳+frontend 五页面板接真 API）。引擎进度机制按设计定案落地。验收=go build 单 exe+go test 全绿；--dev 或 exe 起来后新建一条 mock 靶站侦察任务看到模块进度与结果表格、证据包导出按钮在位、零对话组件。」

### 1.1 对齐远端（Kur1sulab/src-recon-tool@b83d5b3）✅
- `git remote -v` → `origin git@github.com:Kur1sulab/src-recon-tool.git (fetch/push)`——指向正确远端。
- `git cat-file -t b83d5b3` → commit；`git log --oneline -1 b83d5b3` → 「feat: 资产档案 + 证据包（report 模块…）测试扩到 41 项」；reflog `HEAD@{14}: pull --ff-only: Fast-forward`——远端对齐确实发生且 b83d5b3 在本仓历史内。
- 「本地 origin 误指旧账号需 set-url」的**事前状态无法事后验证**（remote-url 变更不进 reflog），仅证实终态正确。

### 1.2 go.mod ✅
`desktop-go/go.mod:1-10`：`module recon-desktop`，go 1.24，唯一直接依赖 `github.com/jchv/go-webview2`，indirect 仅 go-winloader、x/sys。

### 1.3 go-webview2 壳 ✅
- 窗口创建 `main.go:112-127`（`webview2.NewWithOptions`，标题「侦察工作台 · src-recon-tool」，尺寸来自记忆）。
- 原生配套 `desktop.go`：窗口尺寸记忆 window.json（:37-65，clamp 960x640~7680x4320、坏文件回默认）、单实例命名互斥（:111-123）、原生 MessageBox（:126-133）、user32 GetWindowRect 采样（:94-108）。
- 退出顺序 `main.go:94-99,156-161`：停服务 → `runner.StopAll()` 杀扫描进程树 → 存窗口尺寸。

### 1.4 127.0.0.1 server 六接口 ✅（命名偏差见 §1.7）
- 只绑回环：`main.go:79` `net.Listen("tcp", "127.0.0.1:"+port)`；请求层复核 `server.go:72-92` localGuard（Host 白名单 127.0.0.1/localhost/[::1] + Origin 同源）。
- 六条路由 `server.go:52-59`：`GET /api/env`、`POST /api/scans`、`GET /api/scans`、`GET /api/scans/{id}`、`POST /api/scans/{id}/stop`、`GET /api/scans/{id}/evidence`（另有 `/` 静态兜底）。api.js:4-9 头注即此契约。
- 全响应 no-store（server.go:94-101）；body 8KB 封顶（server.go:193 MaxBytesReader）。

### 1.5 recon.py 子进程管理（--progress-file JSONL 定案）✅
- 定案证据链：`src/recon.py:175` argparse `--progress-file` + `:34-60` `_emit` 事件落盘 + `tests/test_progress_file.py`（emit 契约单测+子进程端到端冒烟），独立提交 c5a131c「engine(progress): recon.py --progress-file JSONL 落盘+单测」。
- 注入点：`runner.go:188` `append([]string{python, script, "--progress-file", progressPath}, argv...)`——主解析器参数置于子命令前（:187 注释），progressPath 在数据目录 `progress/<id>.jsonl`（:178）。
- 子进程纪律：列表 argv 无 shell（runner.go:189）、`PYTHONUTF8=1`+`PYTHONIOENCODING=utf-8`（:191）、stdout/stderr 原样落 logs/<id>.log 不解析（:192-197）、监视 goroutine 400ms Tailer 游标增量（runner.go:225-249 + progress.go:27-59，半行 pending 缓存不丢事件）、`pipeline_end` 缺失兜底补 fail（:256-261）、状态机 stopped/done/fail（:277-284）。
- 树杀：`killTree` runner.go:334-353——Windows `taskkill /T /F /PID`，失败回退 Kill，已退出进程（ErrProcessDone/EINVAL）幂等成功。

### 1.6 原生三件套五页面板接真 API ✅（页面命名偏差见 §1.8）
- 零构建链原生 HTML/CSS/JS：frontend/ 仅 index.html + css/×2 + js/×6 + DESIGN.md；`go:embed frontend` 打进 exe（main.go:37）；无 package.json/node_modules/TS（find 实证 0 命中）。
- 五页注册与接线（hash 路由 app.js:206-238）：

| 页面 | 视图文件 | 真 API 接线 |
|---|---|---|
| ① 任务列表 | views/tasks.js:87 `API.poll(refresh, 800)` | GET /api/scans（800ms 轮询） |
| ② 新建侦察 | views/new.js:94,114 | POST /api/scans + GET /api/env（白名单下发） |
| ③ 任务详情 | views/detail.js:196 `API.poll(refresh, 800)` | GET /api/scans/{id}（进度/产物/日志尾），终态自动停轮询（:135-136） |
| ④ 证据包 | views/evidence.js:77,123 | GET /api/scans/{id}/evidence → Blob 下载 |
| ⑤ 设置 | views/settings.js:78 | GET /api/env（自检+白名单只读） |

- XSS 面为零：`App.h` 构建器动态数据一律 textContent（app.js:20），grep `innerHTML|insertAdjacentHTML|document.write` 0 命中；CSP `script-src 'self'; style-src 'self'`（index.html:6），grep 内联 `style=` 0 命中。
- 键盘：Ctrl+1..5 切页（app.js:245-256）、Esc 停运行中任务（:258-279）、离线横幅+状态灯（api.js:65-69 + index.html:68-70）。

### 1.7 偏差登记：六接口命名与草案字面不同
草案 Go 施工员提示词字面六名为 `/api/state /api/start /api/stop /api/results /api/history /api/stats`；实现为 RESTful 六路由（§1.4）。**计数=6、127.0.0.1/no-store/输入校验全对齐；语义映射成立**（start→POST scans、state+results→GET scans/{id}、history→GET scans、stop→stop、stats 由前端基于任务列表计算、工具/环境态→/api/env）。计划 goal 原文只说「六接口」未锁名，判：偏差登记、不判缺陷。

### 1.8 偏差登记：五页面板命名与草案字面不同
草案界面提示词五页为「仪表盘/新建侦察/结果/工具/设置」；实现为「任务列表/新建侦察/任务详情/证据包/设置」。仪表盘统计卡未做独立页（任务列表承载）；「工具」并入「设置」运行环境自检；「证据包」独立成页。计数=5、接真 API ✅。同上判：偏差登记。

### 1.9 mock 靶站端到端 ✅（复核员活体复现，零外网）
`python tests/mock_server.py 8799`（stdlib 靶站）+ 自建 exe `--dev --port 8791`（隔离数据目录）：

```
POST /api/scans {"target":"http://127.0.0.1:8799/real","cmd":"api"}
→ {"id":"20261002-062317-4e8e3273","status":"created"}
t=2s → running 2 ["pipeline_start","start"]
t=6s → done 4 ["pipeline_start","start","done","pipeline_end"]（exit_code 0）
progress 事件即 --progress-file JSONL 经 Tailer 进库（时间戳/模块/事件/详情齐全）
artifacts 16 项（api_unauth.json + evidence/127.0.0.1_8799/×5 命中的 meta/repro/snippet）
log_tail 为真实扫描输出（27 候选端点、Swagger UI/OpenAPI 中危命中）
GET /api/scans/{id}/evidence → 200 application/zip 11,553 字节，
zipfile 校验：16 条目、testzip=None、无 `..`/前导`/`/盘符条目
```

「结果表格/证据包按钮」UI 渲染为代码级证实（index.html:161 前往证据包链接、:187 导出按钮、detail.js:97-113 产物表、evidence.js:73-93 下载），真窗渲染未验（§5）。

### 1.10 go build 单 exe + go test 全绿 ✅（复核员亲跑，见 §4）

---

## 2. 铁律核对（读码 + grep 证实）

| 铁律 | 证据 | 结论 |
|---|---|---|
| 零对话组件 | `grep -rniE "聊天\|气泡\|对话\|发送按钮\|计划卡\|chat\|bubble\|assistant" frontend/`→0 命中；`grep -rniE "\bAI\b\|智能体\|agent\|llm" frontend/*.html frontend/js/`→0 命中。交互全为表单/表格/按钮/下拉（index.html 全量读） | ✅ |
| go build 单 exe | §4 亲跑 exit 0，11,188,736 字节单文件；`go:embed frontend`（main.go:37，无 `all:` 前缀，.mimosa 不进 exe）；零前端构建链 | ✅ |
| 白名单闸在位 | `whitelist.go:14-18` 三条目（xycovo.com / 47.100.49.228 / 127.0.0.1:8799）；`Check` :24-101 深校验（控制字符/非 ASCII 拒、`%2e/%2f/%25` 拒、协议仅 http(s)、userinfo 拒、环回仅 8799 端口、域名格式校验）；服务端 `server.go:214-217` 名单外 403。**活体**：evil.com→403、127.0.0.1:8080→403。纵深：args 目标旗标黑名单（server.go:178-181）+ `--progress-file` 前缀拦截（:310-313）+ `ValidateExtraArgs` 按模块精确白名单（fix1_extra.go:42-72，堵 argparse 前缀缩写）。**活体**：`-u`→400、`--ur`→400、`--progress-file`→400、`--progress_file=x`→400。模糊表固化 fix1_whitelist_test.go（staged，90+ 用例子集） | ✅ |
| 应用层零 Python 依赖 | `go version -m`（复核员自建 exe）：依赖仅 go-webview2/go-winloader/x/sys，CGO_ENABLED=0，无任何 Python 运行时；grep Go 源码 python 引用仅在 runner.go（子进程 argv）与 server.go:141（自检上报）；ProbePython 只以固定 argv 跑 `python --version` 与 `import requests, yaml`（runner.go:119-128）。引擎保持 Python 属设计内（铁律 2 原文：弃的是应用语言不是引擎语言） | ✅ |

附带 grep：`src/recon.py` 的 `llm` 子命令已弃用（活体：POST cmd=llm → 400「不支持的子命令」）。

---

## 3. 审计与对抗问题真修复 — 抽查复现（全程零外网）

依据：afcbf98 提交信息「安全修复/可靠性修复」清单 + 各 fix 测试文件头注（engine/fix1_test.go、engine/fix1_extra_test.go、server/fix1_test.go 7 项、store/fix1_test.go、whitelist/fix1_whitelist_test.go）。复核员用自建 exe `--dev --port 8791` 逐项 curl 活体复现：

| # | 对抗项 | 命令要点 | 实测结果 |
|---|---|---|---|
| 1 | 名单外目标 | POST scans target=evil.com | **403**「目标不在授权白名单」 |
| 2 | 私网端口漂移 | target=http://127.0.0.1:8080/ | **403**（环回仅 8799） |
| 3 | args 目标旗标 | args="-u http://evil.com" | **400**「目标由系统按白名单校验后注入」 |
| 4 | argparse 缩写绕过 | args="--ur http://evil.com" | **400**「该子命令不允许的旗标: --ur」 |
| 5 | progress-file 劫持 | args="--progress-file /tmp/x.jsonl" | **400** |
| 6 | 下划线等号形式 | args="--progress_file=/tmp/x" | **400**（前缀匹配生效） |
| 7 | 取值旗标藏目标 | jsintel args="--max-files -u" | **400** |
| 8 | 已弃用子命令 | cmd=llm | **400** |
| 9 | Host 伪造（DNS rebinding） | Host: evil.example | **403**「非本机请求」 |
| 10 | 跨站盲打 | Origin: http://evil.example + POST | **403**「跨站请求」 |
| 11 | 自身 Origin 不误伤 | Origin: http://127.0.0.1:8791 | **200** |
| 12 | 穿越读仓库文件 | GET /..%2f..%2fgo.mod（--path-as-is） | **404**「未知接口」 |
| 13 | 隐藏目录泄露 | GET /.mimosa/reports/x.json | **404**（embed 无 all: 前缀 + hStatic 点段 404 双保险） |
| 14 | 方法不匹配形状 | DELETE /api/scans；PUT /api/scans | **405** + `Allow: GET, POST` |

代码级核实（未逐项活体但读码+单测证实）：根路径直出 index.html 字节不走 FileServer 消 301 自指环（server.go:645-653；活体 root=200）；崩溃恢复 running→fail 对账（store.go:84-94 + 单测）；outDirFor 清洗 `..`/Windows 保留字符且必落 out/ 内（server.go:377-390 + 单测）；证据包超限文件整只跳过留痕不写截断字节（server.go:519-544 + 单测）；现成 zip 条目审计（evidenceZipSafe server.go:555-587，复核员下载包条目全安全）；CSP 不放宽改代码（内联样式 0 命中）。

**14/14 活体对抗全过，未发现回退或假修复。**

---

## 4. 复核员亲跑 go build + go test（原始输出）

```
$ cd desktop-go && C:/Go/go/bin/go.exe version
go version go1.24.1 windows/amd64

$ C:/Go/go/bin/go.exe build -o "$TEMP/recon-review-check.exe" .
BUILD_EXIT=0        # 单文件 11,188,736 字节（go:embed 前端内置，无外部资源）

$ C:/Go/go/bin/go.exe test -count=1 ./...
?   	recon-desktop	[no test files]
ok  	recon-desktop/internal/engine	2.870s
ok  	recon-desktop/internal/server	3.533s
ok  	recon-desktop/internal/store	9.341s
ok  	recon-desktop/internal/whitelist	0.265s
（4 包全绿；测试函数计数 grep '^func Test' = 48：engine 15 / server 22 / store 8 / whitelist 3）

$ C:/Go/go/bin/go.exe vet ./...        → 无输出，exit 0
$ gofmt -l .                           → 空表
$ node --check frontend/js/**/*.js（7 文件）→ 全 OK
```

附：`go version -m` 自建 exe → `vcs.revision=afcbf98… vcs.modified=true`（工作树含 staged 未提交件，见 §6）；CGO_ENABLED=0。

---

## 5. 视觉验收（SKILL: desktop-visual-acceptance）— 代码走查替代

**真窗口未启动**：本复核为无头会话子代理，无 GUI 走查通道；按交付指令「无法起真窗口时以代码走查替代并逐条注明」执行。**因此不打「视觉验收 PASS」，A/B 两层留待第 2 轮真窗走查。**

| SKILL 项 | 结论 | 证据（代码走查） |
|---|---|---|
| A1 标题栏=应用名，无浏览器 chrome | 代码✅ | main.go:117 窗口标题；WebView2 Debug:false 无地址栏 |
| A2 最小尺寸生效 | **部分** | 尺寸 clamp 仅作用于记忆值（desktop.go:20-34），WebView2 选项未设实时 MinWidth/MinHeight，运行中可拖更小（低危，转第 2 轮） |
| A3 尺寸记忆 | 代码✅（真窗未复测） | loadWindow/saveWindow（desktop.go:37-65）+ 每秒采样（main.go:139-154）+ 退出落盘（main.go:159） |
| A4 DPI 双档 100%/150% | **未验** | 未见 PerMonitorV2 manifest 证据；真窗走查项 |
| A5 关窗确认（运行中弹确认/空闲直退） | 代码✅ | main.go:130-134 confirmExit 绑定 beforeunload；store.RunningIDs（store.go:165-175）供判定 |
| A6 单实例 | 代码✅ | 命名互斥 desktop.go:111-123；二实例弹原生框退出（main.go:45-48） |
| B1 横向溢出 | 代码有防线，真渲染未测 | .table-wrap overflow-x:auto（app.css:275）；kv-grid overflow-wrap:anywhere（:547）；≤760px 断点（:615） |
| B2 命中测试 elementFromPoint | **未验**（需真窗） | — |
| B3 表格斑马纹/悬停/滚动 | 代码✅（100+ 行帧率未测） | app.css:301 斑马纹、:304 悬停；数据上限有界（store MaxProgress=2000，store.go:25） |
| B4 焦点环 | 代码✅ | :focus-visible 2px 品牌青描边（app.css:34-36）；输入框 border+box-shadow（:451-455） |
| B5 分段截图留证 | **未拍**（无真窗） | — |
| C1 键盘全覆盖 | **缺 ↑回填**（第 2 轮范围）；其余代码✅ | Ctrl+1..5（app.js:245-256）、Esc 停止（:258-279）、Tab/Enter/Space 原生控件 |
| C2 空/错/载三态 | 代码✅（真渲染未逐页走查） | 空态 tasks.js:56-59、detail.js:71；错态离线横幅 index.html:68-70+表单错误+toast；载态 index.html:53,124 |
| C3 prefers-reduced-motion | 代码✅ | app.css:628 全局动画压制 |
| C4 对比度 ≥4.5:1 | ✅（复核员数值计算） | tx-1/s2=13.22:1、tx-2/s2=7.07:1、tx-3/s2=5.05:1、acc-ink/acc=7.02:1（WCAG 相对亮度公式实算） |
| D1 全流程数据逐字段核对 | API 层✅（§1.9）；UI 渲染未测（无真窗） | 接口字段与 views 读取字段逐一比对一致（api.js 契约注释 vs server.go 响应构造） |
| D2 历史重开/删除/导出 | 导出✅（§1.9 活体）；重开/删除**未实现**（草案 cycleHints[1] 第 2 轮范围） | — |
| D3 断点恢复 | 崩溃对账✅（store.go:84-94+单测）；会话续传无此设计承诺 | — |
| E 判级 | **不判 PASS**；无 high 级视觉缺陷可见于代码层 | — |

---

## 6. 发现与登记（非阻断）

- **P1（流程，须收口）**：迭代日志 `src-recon-tool/docs/GOAL-20261002-go-desktop.md` 复核时点不存在。按草案流程该文件由架构师在复核后追加（draft :166「无则首轮」），但同名的 `pentest/vulnscan-platform/docs/GOAL-20261002-go-desktop.md`（另一项目）已造成路径混淆——本轮指令即指错路径。**架构师补写日志时务必写到 src-recon-tool/docs/。**
- **P2（流程）**：工作树含 5 个 staged 未提交文件：`frontend/DESIGN.md`（新增 267 行）、`frontend/css/tokens.css`（新增 87 行）、`frontend/css/app.css`（重绘 ±520 行）、`README.md`（±11）、`internal/whitelist/fix1_whitelist_test.go`（新增 70 行）。即美术轮产出与白名单模糊表回归**尚未 commit**（铁律 5 每轮收尾 commit）。本复核的 build/test/对抗结论基于工作树（= afcbf98 + 这 5 件），代码本身已验证；提交动作待架构师收口。
- **P3（低）**：desktop.go:4 注释称「非 Windows 平台回退为无壳运行（--dev）」，但无对应非 Windows 构建文件/标签（syscall.NewLazyDLL 为 Windows 专属）——注释与实现不符，跨平台编译不可行。Windows-only 为实际范围，建议改注释。
- **P4（低）**：§5 A2 实时最小尺寸未约束；A4 DPI 未验。
- **未跑项如实声明**：真窗口视觉走查与截图；`-race`（本机 CGO_ENABLED=0 无 gcc）；>64MB 单文件的证据包跳过路径仅单测覆盖未实测；崩溃重启对账仅单测覆盖未实测重启。

## 7. 结论

第 1 轮（骨架轮）验收目标**达成**：desktop-go 从零建齐（go-webview2 壳 + 127.0.0.1 六接口 + recon.py 子进程管理含 --progress-file JSONL 定案 + 原生五页面板接真 API），单 exe 构建与全量测试复核员亲跑全绿，mock 靶站端到端（进度事件→产物→证据包 zip）活体贯通，14 项对抗活体复现全过，四条铁律全数证实。遗留：真窗视觉验收与美术轮收口提交（第 2 轮既定范围）。
