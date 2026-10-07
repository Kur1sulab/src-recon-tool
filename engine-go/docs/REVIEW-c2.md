# REVIEW-c2 — engine-go 第 2 轮独立冷复核

- 复核人：独立复核员-2（与本轮施工/架构师/对抗测试无关，未改动任何生产代码）
- 复核日期：2026-10-02
- 复核对象：`engine-go/` 工作树（= 已提交 c2 两笔 `af5bf7d`/`398ca9e` + **staged 未提交**
  的 fix2/redteam-adv2 改动，共 90 个文件在途，见 §6-P3）
- 方法：只读通读全部 c2 模块源码与测试 → 亲手重跑验收套件 → 在自建 mock 靶站上
  双引擎并排实测取证（paths / api / report 走真实 CLI 二进制，icp/reverseip 走
  自建临时探针、复核后整目录删除）→ 对审计/对抗修复宣称逐条对抗性复验
- 本文所有数字与结论均为复核员本会话亲手执行/亲读所得，命令与出处逐条括注。

---

## 0. 计划正本说明

`docs/GOAL-20261002-engine-go.md`（工作树版 = fix1 提交 6e0c58d 版本，`git diff` 为空）
只记到 **第 1 轮（c1）**，其「遗留（转入 c2/c3）」第 1 条即本轮范围正本：
> all 串联 / asset / reverse / icp / paths / api（27 端点清单 + 取证模式）/ jsintel /
> portscan / poc（YAML 引擎）/ report（资产档案 + 证据包）。

本轮以三份材料为 c2 交付承诺对照：
1. c2 两笔提交信息（af5bf7d「七模块真实现」/ 398ca9e「c2 parity 矩阵」）；
2. `engine-go/README.md` 子命令对照表的 ✅c2 行与已知微差清单；
3. `engine-go/docs/SECURITY-ADVISORIES.md` 第 2 轮附记（fix2 处置背书）。

注：GOAL 文档尚未补写 c2 轮日志（c1 遗留 #5 所述「动工前按 api_unauth.py/report.py
现状再切 IterPlan」属规划侧动作，仓库内不可核）——见 §6-P2。

## 1. 验收套件亲手重跑（复核员本机实跑）

环境：go1.24.1 windows/amd64（`C:/Go/go/bin/go.exe version`），python 3.8.6 在 PATH。

| 命令 | 结果 |
|---|---|
| `go build -o recon-go-review.exe ./cmd/recon-go` | **rc=0** |
| `go build -o recon-go-review-root.exe .`（根兼容入口） | **rc=0** |
| `go vet ./...` | **rc=0，零告警** |
| `go test -count=1 ./...` | **15 个测试包全 ok，0 FAIL**（apiunauth 1.7s / asset 1.5s / cli 1.6s / fingerprint 0.9s / icp 1.4s / mockweb 2.6s / netutil 1.9s / **parity 58.1s** / paths 1.6s / poc 1.3s / **redteam_adv2 7.1s** / report 1.1s / reverseip 1.2s / subdomain 1.9s / toolrun 2.2s；root、cmd/recon-go、jsonx 三处 [no test files]） |

- parity 58.1s 与 redteam_adv2 7.1s 的耗时佐证 Python 探针与对抗场景**真跑**，非静默跳过。
- `go.sum` 含 yaml.v3（c2 引入的仓库唯一第三方依赖，与 README:40 宣称一致）。
- `-race` 仍未执行：本机无 gcc（同 REVIEW-c1 D2，本轮未复跑该不可行项）。

## 2. 计划兑现逐文件核对（GOAL c1 遗留#1 × c2 提交信息 × README 对照表）

GOAL 遗留#1 列 10 项，c2 兑现 7 项；`all`/`jsintel`/`portscan` 按计划留 c3——
`cli.go:323-330` 实测三者均 exit 2（对抗弹幕 T21 亦证），**无静默走错分支**。

| 文件 | 承诺出处 | 核对结果（亲读 + 套件证据） | 判定 |
|---|---|---|---|
| `go.mod` | af5bf7d「poc(yaml.v3)」 | 仅新增 `require gopkg.in/yaml.v3 v3.0.1`，与其余「零依赖」宣称相容 | ✅ |
| `internal/asset/asset.go` | README:33「FOFA/Hunter 原生客户端，key 走环境变量」 | 凭据只读 `FOFA_EMAIL/FOFA_KEY/HUNTER_KEY`（asset.go:129,154）；`dict.fromkeys` 保序去重（:181-189）；`checkURL` 默认 `CheckHTTPURL(u,false)`（:25）；parity ⑦ 解析层内联重放绿 | ✅ |
| `internal/reverseip/reverseip.go` | README:34「hackertarget；域名正则改写为 RE2 兼容 label 校验」 | ParseHackerTarget 与 reverse_ip.py:22-33 逐行为对；RE2 改写见 §5-R2（**附发现**）；parity ② 绿 | ✅（附发现） |
| `internal/icp/icp.go` | README:35「apihz；限频假 200 防御」 | ParseICP 假 200 三重防御（icp.go:47-52 ↔ icp.py:36-37）；fix2 凭据门禁/编码/Follow:false 见 §4 | ✅ |
| `internal/paths/paths.go` | README:37「19 条字典 + 软 404 基线 + 复验」 | PathsList 19 条与 paths.py:20-26 逐条全等；行结构 omitempty 对齐动态键；**注释「18 条」系笔误**（paths.go:14，实 19） | ✅（附琐碎） |
| `internal/apiunauth/apiunauth.go` | README:36「27 端点清单 + 取证三件套」 | Endpoints 亲数 27 条与 api_unauth.py:22-50 逐条全等（含 `≥2 特征` 规则 ：80-86）；classify/基线过滤/复验/取证落盘逐段对齐；parity ③⑥ 绿 | ✅ |
| `internal/poc/poc.go` | af5bf7d「poc(yaml.v3)」 | Matcher/condition and/or 与 poc_engine.py:30-43 全等；畸形/缺模板路径实测优雅降级（弹幕 T16a/b） | ✅ |
| `internal/report/report.go` | README:42「资产档案 + 证据包 zip」 | Collect 11 键对齐 report.py:42-56；RenderMD 逐行对齐（§3 实测全等）；PackEvidence arcname 相对 out/ + `..` 按段复检（:447-466）+ ZipStamp 唯一性与 .part 原子改名（fix2 P2，:30-37,478-492） | ✅ |
| `internal/cli/cli.go` | af5bf7d「cli 七子命令拆出真实现」 | asset/reverse/icp/api/paths/poc/report 七案全部真实现并接 MakeOutdir；knownCmds 14 命令与 recon.py 子解析器对应 | ✅ |
| `internal/parity/parity_c2_test.go` | 398ca9e「黄金四套 + render_md 逐行 diff + paths/api 全链路 + arcname/成员 + FOFA/Hunter 重放」 | 8 个 parity 测试全带 `RequiresPython`；本轮套件实跑全绿（parity 58.1s） | ✅ |
| fix2 测试件（`fix2_cli_test.go` 5 例 / `icp/fix2b_test.go` 2 例 / `netutil/fix2_netutil_test.go` 3 例 / `subdomain/fix2b_test.go` / `toolrun/fix2b_test.go` 3 例 / `report/fix2_test.go` 3 例 / `redteam_adv2/redteam_adv2_test.go` 4 例） | SECURITY-ADVISORIES 第 2 轮附记 | 全部在本轮 `go test -run … -v` 定向复跑绿（§4） | ✅ |

README 对照表自述（10 实现 / 3 项 c3 / llm 弃用）与 `cli.go` dispatch 实际分支一一相符。
**逐文件核对未发现虚报交付。**

## 3. Go/Python 并排语义对照（复核员自建 mock 场景实测）

靶站：仓库正牌 `tests/mock_server.py` 起 `127.0.0.1:8799`（复核员亲手启动）；
Python 侧驱动脚本与 Go 侧二进制各自独立 out 目录，互不污染。

### M1 paths + api + report 全链路（真实 CLI 二进制，/real 场景）

- 命令：`recon-go-review paths|api -u http://127.0.0.1:8799/real` + `report -t http_127.0.0.1_8799_real`
  vs Python `modules.paths.run_paths / api_unauth.run_api / report.run_report` 同参。
- **paths 存活 5 条全等**：`["/robots.txt","/.env","/swagger-ui.html","/actuator","/actuator/env"]`。
- **api 存活命中 5 条全等**（env/heapdump/swagger/v3-docs/actuator，`live_hits=5`、
  `probed=27`、`soft404_filtered=0` 双侧一致）；digest 双引擎逐条相等
  （如 heapdump `d1e4c8d0940e2b3f`）→ 截断后哈希口径一致。
- **report.md 剥 `\r`+归一时间行后 diff 为空（逐行全等）**——render_md 移植的最硬证据。
- 证据链三件套：`evidence/` 目录树 15 文件**双引擎全等**；`response.snippet.txt`
  全部字节级相等；`meta.json` 结构全等（时间归一后）；**zip 成员名单 15 项全等**
  （arcname 相对 out/ 口径一致）。

### M2 icp（自建临时探针：同一 httptest stub 喂双引擎，复核后探针目录已删）

- parse 层 8 个黄金 payload 双引擎对照：**6/8 全等**；2 个「非 dict JSON」漂移见 §5-F4。
- query 层同 stub 三场景：`ok`（正常备案）与 `limit`（code=200+查询失败）双侧
  结构全等；`redir`（302 跳板）实测 **README 已知微差 #6 的活体确认**——Python
  `follow=False` 不生效仍跟随并拿到结果（filed=true），Go `Follow:false` 停在
  302（`请求失败: HTTP 302`），凭据 query 未离开本机。该差异已备案，不判缺陷。
- 探针过程披露：首轮探针存在复核员自身 bug（过早恢复 `icp.APIHZURL`），导致
  Go 侧发出 **1 次真实 cn.apihz.cn 请求（假凭据 id=REVIEW-ID，被接口以「id参数
  异常」拒绝）**；当即修正探针后重跑，全部流量收敛本机 stub。除该 1 次外，
  本轮全部验证零外网。

### M3 reverseip（同一探针内，同输入对照）

- 常规输入（大小写/尾点/脏行/ip6.arpa）双引擎全等；
- 对抗输入 `aa.-bb.com`：Python 保留、Go 剔除——**RE2 改写并非严格等价**，见 §5-R2。

## 4. 审计与对抗问题真修复抽查

| 宣称 | 复核方式与证据 | 判定 |
|---|---|---|
| fix2 P1：icp 凭据防 302 外送（Follow:false） | `TestICPKeyExfilViaRedirect` 绿（跳板零请求）；§3-M2 redir 场景活体复证；icp.go:98-101 注释与实现一致 | ✅ |
| fix2 P1：domain 经 url.Values 编码防参数注入 | `TestICPDomainQueryInjection` 绿（断言 `domain=a%26key%3D…`）；CLI 实测 `icp -d 'a&key=ATTACKER_INJECTED'` → **exit 2**（弹幕 T13 修复前 exit 0 照单发查询） | ✅ |
| fix2 P3：CLI 输入门禁（reverse 严格 IP / icp 域名形状） | 真实二进制实测：`reverse -i '8.8.8.8&x=1'`→exit 2、`icp -d '../../etc/passwd'`→exit 2、`icp -d '例えテスト.jp'`→exit 2；单测 `TestReverseRejectsNonIP`/`TestICPRejectsBadDomainShape` 绿。Python 侧维持原行为属 README 已知微差 #8 备案 | ✅ |
| fix2 P3：MakeOutdir Windows 保留设备名 | 实测 `report -t CON`→`out\CON_`、`report -t nul`→`out\nul_`（弹幕 T10/T11 修复前为 `out\CON`/mkdir 失败）；Python `recon.make_outdir('CON')`→`out\CON_` 双侧同步亲测；`TestMakeOutdirDefusesReservedStems`/`TestSafeFilenameWindowsReservedStems` 绿 | ✅ |
| fix2：ONEFORALL_HOME 组件级清洗 | `TestRunOneForAllRejectsTraversalHome`/`TestRunOneForAllMissingHome` 绿；oneforall.go 组件剔除+盘符重组+存在性复核亲读确认 | ✅ |
| fix2 P1：HopPolicy 逐跳校验接线 | `TestHopPolicyPublicEntryBlocksPrivateLanding`/`TestHopPolicyPrivateEntryAllowsPrivateLanding` 绿；api/paths/poc/verify/取证复请求/fingerprint/PickBase 八处接线亲读确认；**但 README「全部 Follow 调用点」表述过宽**（见 §5-F1） | ✅（附发现） |
| fix2 P2：zip 并发覆盖 + arcname `..` 子串误杀 | `TestZipStampConcurrentUnique`/`TestPackEvidenceKeepsDotDotSubstringNames`/`TestPackEvidenceArcnamesRelative` 绿；report.go `.part`+`Rename` 原子化亲读；Python report.py:204-209 同步（微秒+seq+PID）亲读确认 | ✅ |
| fix2 audit low#3：落盘 JSON 键型/形态 | `statusOrNil/errOrNil`（apiunauth.go:99-111）+ `BaselineResult.MarshalJSON` unknown 两键形态（baseline.go:51-61，`TestBaselineUnknownMarshalTwoKeys` 绿） | ✅ |
| fix2 audit low#4：render_md ICP 确定性 | Go 按域名排序取前 5（report.go:147-155，注释自认与 Python sorted-glob 序不同但均可复现）；`TestRenderICPDeterministic` 绿 | ✅ |
| fix2 audit low#7：重复旗标 last-wins | `TestPickAliasLastWins`/`TestPickIntAliasLastWins` 绿（args 位置序判定实现正确） | ✅ |
| 凭据纪律（CWE-798 类）：源码零可用凭据 | `TestQueryICPSkipsWithoutCredentials` 绿；Python icp.py:48-52 同步亲测（无 env → 跳过文案一致）；`TestICPFailureLogNoKey` 绿（失败日志/落盘无 key）；全仓 grep 未见 apihz/fofa/hunter 真实凭据字面量 | ✅ |
| fix1 抽查（应持续有效） | digest.go:15 仍为 `sha256.Sum256` 前 16 hex；`TestSafeFilename`/`TestMakeOutdirSanitized` 复跑绿 | ✅ |
| redteam-adv2 弹幕归档 | `battery_results.txt` 21 项（T8/T9/T12 失败即 exit 1 上抛，T16b 畸形 YAML 优雅降级，T17 query 夹带元数据地址不解析，T18/T21 exit 2）——**注意该结果是 fix2 前基线**，本轮已用当前二进制复核 T10/11/13/14/15/20 全部翻转 | ✅ |

## 5. 发现（均非阻断）

- **F1（低·文档过表述 + 加固盲区）**：README 已知微差 #5 称「fix2 全量接线：Go
  **全部** Follow 调用点……经 HopPolicy 逐跳校验」，随后枚举的清单不含
  `reverseip.go:86`（Follow:true，无 HopCheck）与 `subdomain.go:58/94`
  （crt.sh/certspotter 通道，入口做过 CheckHTTPURL 但 302 落点不复检）——这三处
  与 Python 现状 parity 一致、且数据源无凭据入 query，风险低；但「全部」二字与
  代码不符，且 crt.sh 若被 302 打向内网/元数据，Go 侧不设防。建议 c3 要么补齐
  接线，要么把 README 收窄为如实清单。
- **F2（低·证据文件渲染漂移）**：repro.md「存活复验」行，Python 渲染
  `[{'status': 200, 'size': 87, 'digest': '…'}]`，Go 渲染 `[{200 87 …}]`
  （`%v` 结构体）——数据同、形态异。交付给报告撰写人时可读性略差，建议改
  json.Marshal 渲染并与 Python 对齐。
- **F3（低·空列表落盘形态）**：paths.json 的 `notes`（无命中时 `alive` 同理）
  Go 落 `null`、Python 落 `[]`（paths.go:49 nil slice）；api_unauth.json `hits`
  空时同理。fix1 已为 subdomains_live 修过同类形态（README:105-107），此处漏网；
  JSON 语义消费方不受影响，逐字节 diff 消费方（如未来桌面壳）会感知。
- **F4（低·错误文案漂移）**：`ParseICP` 对「合法 JSON 但非 dict」的 payload：
  `[1,2,3]` → Go「响应非 JSON」vs Python「响应格式异常」；`null` → Go 落入
  code!=200 兜底「查询失败」vs Python「响应格式异常」。两案 `filed=false` 一致、
  不影响判定，仅 msg 文案漂移，且仓内 parity 黄金集（`<html>502</html>`）未覆盖。
- **R2（低·等价性宣称不严格）**：reverseip.go:24-48 声称 label 校验与
  reverse_ip.py:18 正则「等价性由黄金用例与 parity 钉死」；实测 Python 正则的
  `(?!-)/(?<!-)` 只护**首段**，非首段允许 `aa.-bb.com`/`bb-.cc.com`，Go 侧全段
  拒绝——**Go 更保守（多剔不漏收）**，方向安全，但「等价」表述应改为「收紧」。
- **琐碎**：paths.go:14 注释「18 条」实为 19 条（README 与运行时均正确）。
- **D1（承接 REVIEW-c1，仍未闭环）**：进度事件错误路径契约——本轮实测 Go 对
  `verify`（缺 -d）发 4 条事件、对 `llm` 发 4 条；Python 分别为 **0 条（无文件）**
  与 **2 条**，退出码两侧均 2。c1 建议的「c2 轮定案」未发生，README 亦未备案该
  差异。桌面壳消费侧 Go 行为反而更完整，建议 c3 明确：对齐或双侧备案。

## 6. 流程记录

- **P1（红线核查）**：本轮验证全程零外网（除 §3-M2 披露的 1 次探针事故，假凭据、
  即改即止）；mock 靶站为本仓库 `tests/mock_server.py`；未触碰任何真实目标
  （运维者自有域名与服务器 IP 已脱敏）/ 任何未授权目标。
- **P2（计划正本缺口）**：GOAL 文档仍停在 c1 轮，无 c2 轮日志与验收线声明；
  本轮以提交信息+README+advisories 为对照正本。建议编排方在提交 fix2 时把 c2
  轮日志与本文一并入库，保持「轮次日志」连续性。
- **P3（在途改动）**：fix2 全部修复（engine-go 生产代码 12 文件 + 测试 9 件 +
  Python 3 文件 + redteam-adv2 证据 60+ 件）当前 **staged 未提交**。本轮复核
  对象=工作树状态；提交时建议 CI 复跑全量测试（tests.yml 与 Go workflow 均已
  在 189f4ca 就位，路径触发 engine-go/ 应能覆盖）。
- **P4（复核产物纪律）**：临时探针目录 `internal/reviewc2probe/` 已整目录删除，
  `git status` 复核无残留；并排对照产物全部位于系统临时目录，未写入仓库；
  本轮仅新增本文档。

## 7. 复核结论

**第 2 轮（c2）验收通过。** 验收套件复核员亲手复跑全绿（15 包 ok，parity 58.1s
真实跑 Python）；GOAL 遗留#1 的 7 项 c2 交付逐文件核对无虚报，`all`/`jsintel`/
`portscan` 按计划留 c3 且 exit 2 防呆；四个模块（paths/api/report 走真实 CLI、
icp 走同 stub 探针）双引擎并排实测——report.md 逐行全等、证据链 15 文件与 zip
成员名单全等、判定流水线零漂移；fix2 的 13 项审计/对抗修复抽查全部实锤（含
弹幕修复前基线 → 当前二进制的行为翻转对照）。6 条新发现（F1 文档过表述、
F2/F3/F4 低危形态漂移、R2 等价性表述、1 琐碎）+ 1 条 c1 遗留未闭环（D1）+
3 条流程记录，均不阻断验收，留 c3 轮处置。

复核员声明：未修改任何生产代码；临时探针已删净（git status 无残留）。
