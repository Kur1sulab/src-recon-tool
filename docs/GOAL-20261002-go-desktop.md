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
*第 2 轮起按轮追加。*
