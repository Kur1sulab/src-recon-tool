# REVIEW-c1 — engine-go 第 1 轮独立冷复核

- 复核人：独立复核员（与本轮施工/架构师无关，未改动任何生产代码）
- 复核日期：2026-10-02
- 复核对象：`engine-go/` 工作树（含 **staged 未提交** 的 fix1 修复，见 D4）
- 方法：只读通读全部源码/测试/文档 → 亲手重跑验收三件套 → 对同一 mock 靶站
  双引擎并排实测取证 → 对审计/对抗宣称逐条对抗性验证
- 本文所有数字与结论均为复核员本会话亲手执行/亲读所得，命令与出处逐条括注。

---

## 0. 计划正本说明（重要前置）

任务给定的计划文档路径 `src-recon-tool/docs/GOAL-20261002-engine-go.md` **不存在**
（`src-recon-tool/docs/` 仅有 `audit-20260924.md`，复核员 `find` 全仓与 home 目录实证）。
全盘检索发现同名文件位于本机用户目录下另一项目（路径已脱敏）`pentest/vulnscan-platform/docs/GOAL-20261002-engine-go.md`，
但其内容描述的是**另一个项目**（vulnscan-platform 的 autoscanner Go 重写：
gate/runner/writers/fidhash 架构、autoscanner-go.exe），与本仓库 engine-go
（recon-go：netutil/subdomain/fingerprint/mockweb/toolrun/parity/cli）结构完全不同，
**不能**作为本仓库计划正本（详见 D3）。

本轮以仓库内权威替身作为计划对照：
1. 4 条 `engine-go(c1)` git 提交信息（2726c7a / 88373cc / 3c76fa0 / c76962d）——逐模块交付承诺；
2. `engine-go/README.md` ——14 子命令对照表、移植铁律（外部工具不重写）、关键语义清单、备案微差 5 条；
3. `engine-go/docs/SECURITY-ADVISORIES.md` ——静态扫描 advisory 处置背书（fix1）；
4. `docs/audit-20260924.md` ——Python 侧审计基线（F1-F8），Go 侧宣称移植其修复语义。

---

## 1. 验收三件套亲手重跑（复核员本机实跑）

环境：go1.24.1 windows/amd64（`C:/Go/go/bin/go.exe version`），python 3.8 在 PATH。

| 命令 | 结果 |
|---|---|
| `go build -o recon-go.exe ./cmd/recon-go` | **rc=0** |
| `go build -o recon-go.exe .`（根兼容入口） | **rc=0** |
| `go vet ./...` | **rc=0，零告警** |
| `go test -count=1 ./...` | **7 包全 ok，63 PASS / 0 FAIL / 1 SKIP**（cli 0.288s / fingerprint 0.445s / mockweb 1.966s / netutil 1.172s / **parity 15.767s** / subdomain 0.856s / toolrun 0.752s） |

- SKIP 仅 `TestDNSLookupUnresolvableHost`：复核员实测本机
  `socket.getaddrinfo('definitely-not-a-host.invalid')` 返回 **198.18.0.162**
  （Clash fake-ip 环境），测试按设计自动放行（README「实测白名单红线」节明文备案）——
  **环境性行为，非代码缺陷**。
- parity 非跳过实跑：`TestParityBaseline 3.43s / TestParityFetch 3.51s /
  TestParityFingerprint 1.72s / TestParityHTTPProbe 0.77s / TestParityVerifySubs 0.57s /
  TestParityOneForAll 0.90s` 全 PASS——耗时佐证 Python 真被调用。
- `go test -count=5 -race ...` **未能执行**：本机无 gcc（CGO_ENABLED=1 后
  `C compiler "gcc" not found`），以 10 倍压测替代（见 D2）。

## 2. 计划兑现逐文件核对（对照提交信息 + README 目录结构 + 14 子命令表）

| 文件 | 承诺出处 | 核对结果 | 判定 |
|---|---|---|---|
| `go.mod` | README:20「零第三方依赖」 | module+go1.24，无 require 段 | ✅ |
| `main.go`(13 行) / `cmd/recon-go/main.go`(13 行) | c76962d「双薄壳入口行为等价」 | 均仅 `os.Exit(cli.Run(os.Args[1:]))`；两者各自 build rc=0 | ✅ |
| `internal/cli/cli.go` | 3c76fa0「14 子命令 CLI」+ README:25-45 对照表 | 14 命令全注册（knownCmds）；真实现 subdomain/verify/fingerprint；llm 与 10 个占位实测 **exit 2**（见 §4-M3/M4）；`help`/无参数/未知子命令实测 rc=0/1/2 与 README:44 一致 | ✅ |
| `internal/cli/progress.go` | fix1 审计 medium#4 | `--progress-file`/`--progress-file=`/`RECON_PROGRESS_FILE` 兜底、help/未知全局不发事件——单测 3 件套全绿 + CLI 实测；**错误路径事件数与 Python 漂移**（发现 D1） | ✅（附发现） |
| `internal/jsonx/jsonx.go` | jsonx 底座（2726c7a） | SetEscapeHTML(false)+SetIndent(2)+去尾换行 = `ensure_ascii=False, indent=2` 语义 | ✅ |
| `internal/netutil/fetch.go` | 2726c7a + README:66-74 关键语义 | 协议白名单/先截断后哈希/utf-8 ignore/4xx5xx ok=true/重定向 10 跳超限返回最后 30x/headers 小写后写覆盖/HopCheck/errReason 剥 URL——均有对应单测（`netutil_test.go` 9 例 + `fix1_netutil_test.go` 3 例）全绿 | ✅ |
| `internal/netutil/urlcheck.go` | README:75-82「Python 3.8 私网全集」 | v4 14 段 + v6 6 段手工表；`TestIPBlockedMatchesPython` 动态 python 探针 31 地址逐 IP 对照 PASS | ✅ |
| `internal/netutil/safeio.go` | README:83-90 + fix1 对抗 P2 | 白名单/截 64/剥点/剔 `..`/withinBase 包含校验/Windows 保留设备名主干补 `_`——`TestSafeFilename`（含 `"../../etc/passwd"→"_.._etc_passwd"`）等 PASS | ✅ |
| `internal/netutil/baseline.go` | audit F1/F2 移植 | SameShape/Baseline 五分类/IsBaseline redirect 特判/VerifyLive——§4-M1 双引擎五场景全等 | ✅ |
| `internal/netutil/digest.go` | SECURITY-ADVISORIES「SHA-1 已按 CWE-327 双引擎迁移」 | staged diff 实证 `-crypto/sha1 +crypto/sha256`；双引擎同一 URL digest 全等 `7b88312a1d3958c4`（§4-M1）| ✅ |
| `internal/subdomain/subdomain.go` | 3c76fa0 + README:55 | OneForAll→subfinder(可选增强)→crt.sh(3 次退避)→certspotter 降级链；边界校验失败 0 重试降级（fix1 low#7，`TestChannelBoundaryCheckDegradation` 断言 sleeps=0）；控制字符清洗（对抗 INFO）| ✅ |
| `internal/subdomain/verify.go` | fix1 high#1 + medium#3 | P0 竞态修复 staged diff 实证 `map[int]ProbeResult`→`make([]ProbeResult,…)`（互不重叠下标写）；死亡行 `ips:[]/http:{}` 序列化对齐（`TestVerifyRowJSONMatchesPythonShape` 断言逐字节）| ✅ |
| `internal/fingerprint/fingerprint.go` | 3c76fa0「28 规则逐字移植」 | `TestRulesInventory` 钉死 28 条；复核员将 28 条规则与 `fingerprint.py:19-47` 逐条肉眼比对，name/where/pattern/type 零漂移 | ✅ |
| `internal/mockweb/mockweb.go` | 88373cc「与 mock_server.py 逐字节对齐+漂移守卫」 | `TestRealConstantsMatchPythonMock` 经 base64 导出 Python 常量逐字节比对 PASS（SPA_SHELL + REAL 7 键）；`fppage` 场景为 Go 靶站扩展且注释明示（供双引擎共打）| ✅ |
| `internal/toolrun/oneforall.go` + `scanutil.go` | 88373cc「子进程适配层+路径纪律」 | 参数数组 `exec.CommandContext`（无 shell）；domain/out/home 三重纪律实测拦截（§5）；RECON_PYTHON 优先解释器解析 | ✅ |
| `internal/parity/parity.go` + `parity_test.go` | 88373cc/3c76fa0「parity 矩阵」 | 6 组断言（baseline/fetch/fingerprint/probe/verify_subs/oneforall）全 PASS；python 缺席自动 skip 铁律在 `RequiresPython` | ✅ |
| `testdata/oneforall_fake.py.txt` | 88373cc | 存在；双引擎 adapter 输出 4 项全等（§4-M2） | ✅ |

README 对照表自述状态（3 实现 / 10 占位 / 1 弃用）与代码 `dispatch` 一一相符；
「已知微差」5 条均有对应代码注释留档。**逐文件核对未发现虚报交付。**

## 3. Go/Python 并排语义对照（复核员自建 mock 场景实测）

靶站：仓库正牌 `tests/mock_server.py` 起 `127.0.0.1:8799`（复核员亲手启动）；
Go 侧另用临时探针（复核员自建自删目录，未触碰生产代码，已删并核验 git 状态无残留）。

### M1 netutil（baseline / fetch / verify_live）——audit F1/F2 移植语义

双引擎打同一靶站，输出并排（Python `modules.netutil` vs Go `internal/netutil`）：

| 场景 | kind | status | size | ctype | 双引擎 |
|---|---|---|---|---|---|
| soft404（SPA 外壳） | soft404 | 200 | 134 | text/html; charset=utf-8 | **全等** |
| waf（全局 403） | uniform403 | 403 | 46 | text/html | **全等** |
| loginredirect（302 环） | redirect | 302 | 0 | text/html | **全等** |
| empty（标准 404） | normal | 404 | 29 | text/html | **全等** |
| api404（JSON 软 404） | soft404 | 200 | 68 | application/json | **全等** |

- `fetch /real/.env`：ok/status/size/digest/ctype 五字段全等，
  **digest=7b88312a1d3958c4 双引擎一致** → SHA-256 迁移两侧同步（CWE-327 整改实证）。
- `verify_live /real/actuator (tries=2, expect_body=_links)`：live=true、
  attempts 两条全等（87B / 757209d0e6834ea4 ×2）、note「两次一致」全等。

### M2 subdomain（OneForAll 适配器 + verify_subs 行形态）

- 同一 fixture（`testdata/oneforall_fake.py.txt`）：Python `_from_oneforall` 与 Go
  `toolrun.RunOneForAll` 输出**逐元素全等**
  `["MAIL.fixture.example","api.fixture.example","dev.fixture.example","mail.fixture.example"]`
  （尾逗号/脏行/前导点/大写去重排序语义一致）。
- `verify_subs(["127.0.0.1"], do_http=false)`：行 JSON 双引擎全等
  `{"host":"127.0.0.1","ips":["127.0.0.1"],"alive":true,"http":{}}`（含空值形态）。
- CLI `verify -d 127.0.0.1 -w 4` 端到端：**stdout 逐字相同**；
  `subdomains_live.json` 剥 `\r` 后 diff 为空；`subdomains_live.txt` 仅 CRLF/LF
  行尾差（README 备案微差 #4）。

### M3 fingerprint + 目录名（经真实 CLI 二进制，双端各自 out）

- `/real/swagger-ui.html`：两引擎 `fingerprint.json`（剥 `\r`）diff 为空——
  `[{"name":"Swagger UI","type":"api"}]`；**产物目录名双引擎一致**
  （`out/http_127.0.0.1_8799_real_swagger-ui.html/`）→ MakeOutdir/make_outdir 同名实证。
- `/soft404/x`（SPA 假页）：双引擎均 **0 命中**「无」——假阳性零（audit F1 语义）。
- `/waf/x`（403）：双引擎同文案 `[!] 指纹识别请求失败: 403`。
- 错误路径（`http://127.0.0.1:1/x?api_key=TOPSECRET_*`）：双引擎失败文案均
  **不含 URL 与 key**（Go `errReason` 剥前缀修复实测生效）；原因文本措辞各异
  （`<urlopen error [WinError 10061]…>` vs `dial tcp …: connectex: …`）——
  即 README 备案微差 #2 的 %s 原生错误文本，可观测语义一致。

### M4 进度事件流（额外对照，发现 D1）

- `llm -d x.com`（exit 2 路径）：Python 仅 2 条事件（无 fail/pipeline_end），
  Go 4 条——**漂移，见 D1**。
- 缺必填参数（`subdomain` 无 -d）：Python **0 条**（argparse 阶段退出），Go **4 条**。
- 成功路径（单测 `TestProgressFileDoneContract` 钉死 4 事件键序）与 Python
  `recon.py:34-43/209-272` 契约一致；退出码契约（rc=1/2）双引擎实测一致。

## 4. 审计与对抗修复抽查（对照 audit-20260924 与 SECURITY-ADVISORIES）

| 宣称 | 复核方式与证据 | 判定 |
|---|---|---|
| fix1 high#1：VerifySubs 并发写 map → fatal（30 连跑 16 崩） | staged diff 实证 `map[int]ProbeResult`→`[]ProbeResult`（verify.go:159，写互不重叠下标）；`-race` 不可跑（无 gcc，见 D2）→ 以 `go test -count=10 -run TestVerifySubs…`（200 轮并发探活）**全绿**替代 | ✅（-race 未跑，如实报告） |
| audit F1/F2：软 404 基线 + 存活复验移植 | §3-M1 五场景双引擎全等（0 误报）；verify_live 全等 | ✅ |
| audit F5 类：目录穿越 | 真实 CLI `verify -d '..\..\pwned'` → 目录落在 `out/_.._pwned`，`out/` 外（/tmp/review-c1/pwned 等）实测不存在；Python 同输入同收敛（`out\_.._pwned`） | ✅ |
| fix1 medium#2/low#6：MakeOutdir 清洗+错误上抛 | `TestMakeOutdirSanitized`（8 组含 `..\..\trav`/`..`/空）/`TestMakeOutdirErrorPropagates` PASS | ✅ |
| fix1 medium#3：live.json 空值形态 | `TestVerifyRowJSONMatchesPythonShape`（死亡行逐字节断言）PASS + §3-M2 实测 | ✅ |
| fix1 medium#4：--progress-file | 单测 3 件套 PASS + CLI 实测；错误路径漂移记 D1 | ✅（附发现） |
| fix1 low#5：error 字段剥 URL（防 key 入日志） | `TestFetchErrStripsURL` PASS + §3-M3 错误路径实测无泄漏 | ✅ |
| fix1 low#7：通道边界校验失败 → 0 重试降级 | `TestChannelBoundaryCheckDegradation` 断言 sleeps==0 PASS（对齐 Python ValueError 异常降级） | ✅ |
| fix1 low#9：IsIP 去 TrimSpace | `TestIsIPNoTrim` PASS（`" 1.2.3.4 "` 判假） | ✅ |
| 对抗 P2：Windows 保留设备名 | `TestSafeFilenameWindowsReservedStems` 10 用例（con.txt→con_.txt 等）PASS | ✅ |
| 对抗 INFO：crt.sh 控制字符清洗 | `TestCollectNamesStripsControlChars` PASS；Python 侧同位清洗在 `subdomain.py:69-72`（staged 工作树）亲读确认，剔除时机注释双侧同位 | ✅ |
| SECURITY-ADVISORIES 消毒节点 2/3/4（OneForAll domain/out/home 纪律） | 复核员自建对抗探针实测：`a/b`、`../evil`（domain）→ 拦截；`../../escaped`（out）→ 拦截且目录不存在；home 含 `..` → 拦截；5 场景零逃逸产物 | ✅ |
| 消毒节点 5：无 shell 子进程 | 生产代码 `grep -rn "exec\.Command\(|cmd /c|COMSPEC|sh -c|bash -c" internal/ cmd/ main.go`（剔测试）仅命中 `parity.go:38`（测试基建，`python -c` 参数数组）——**零 shell** | ✅ |
| advisory 计数 5→3 与 seal | `~/.mimosa/security-scans/project-c29f…/seal.json` digest=**sha256:cacf864c…** 与 advisory 头一致；扫描史 21-44-52/21-53-40 两轮 **5 条** → 22-03-36/22-06-47 **3 条**；最终 3 条（main.go:13 / cmd/recon-go/main.go:12 高、subdomain.go:159 中）与 advisory A/B 逐条对上 | ✅ |
| SHA-1→SHA-256（CWE-327） | digest.go staged diff + §3-M1 双引擎 digest 全等 | ✅ |

## 5. 发现（均非阻断）

- **D1（低·语义漂移未备案）进度事件错误路径契约**：Python 对「已知子命令缺必填参数」
  在 argparse 阶段 exit 2、**0 条事件**（实测）；对 `llm` 经 `sys.exit(2)`→
  `except SystemExit: raise`（recon.py:262-263）跳过收尾、**仅 2 条**。
  Go 对两场景一律 **4 条**（pipeline_start→start→fail→pipeline_end，实测）。
  退出码一致（rc=2）、成功路径一致；但 progress.go:10-13 与 README「事件序对齐
  recon.py:195-257 逐项一致」的表述在错误路径不成立。对桌面壳消费者 Go 行为反而
  更完整（有终态事件），建议 c2 轮定案：对齐 Python 豁免或双侧备案为有意差异。
- **D2（信息·环境）**：`-race` 因本机无 gcc 不可执行；P0 竞态修复以 10 倍压测 +
  代码审读为替代证据。建议有 C 工具链的环境补一次 `go test -race ./...`。
- **D3（信息·流程）**：请求的 GOAL 文档在 `src-recon-tool/docs/` 缺失；
  `pentest/vulnscan-platform/docs/` 下同名文件属另一项目（autoscanner-go），
  已核对不能混用。建议本仓库补立 GOAL 迭代日志（姊妹项目已有先例）。
- **D4（信息·流程）**：fix1 全部修复（engine-go 18 文件 + Python 3 文件）当前
  **staged 未提交**。本轮复核对象=工作树状态；提交时建议 CI 复跑全量测试。
- **D5（琐碎）**：`engine-go/README.md` 第 83-90 行与第 99-100 行「安全落盘」条目
  重复（fix1 插入时未删旧段），建议顺手去重。

## 6. 复核结论

**第 1 轮（c1）验收通过。** 双入口 build、vet、全量 test（63 PASS/0 FAIL/1 环境性
SKIP）复核员亲手复跑全绿；计划兑现逐文件核对无虚报；三个模块（netutil/subdomain/
fingerprint）在真实 mock 靶站上双引擎并排实测全等（备案微差之外零语义漂移）；
10 项审计/对抗修复抽查 9 项实锤、1 项（-race）环境受限如实报告；静态 advisory
数字（5→3、seal、逐条处置）与 Mimosa 扫描档案一致。1 条新发现（D1 进度事件
错误路径漂移，低危）+ 4 条信息级记录，均不阻断验收，留 c2 轮处置。

复核员声明：未修改任何生产代码；临时探针目录已删除，`git status` 复核无残留
（仅新增本文档）。
