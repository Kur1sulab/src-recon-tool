# REVIEW-c3 — engine-go 第 3 轮独立冷复核

- 复核人：独立复核员-3（与本轮施工/架构师/对抗测试无关，未改动任何生产代码）
- 复核日期：2026-10-03
- 复核对象：`engine-go/` 工作树 = **HEAD `8b9717f`**（c3 六笔：`108ce88` fix2/redteam-adv2 入库 →
  `dcfc220` PARITY/TEST-PORT → `82aeef1` 收口拍板 → `3eb2c9e` 私网表 3.13 口径 → `30ee014` CI 探针阈值 →
  `8b9717f` parity CI 自跳）**+ staged 未提交 20 文件的 fix3 在途改动**（audit high#1/medium#2/3/4、
  low#5/6/7/8，含 `src/modules/netutil.py` 双侧同步），见 §6-P3
- 方法：只读通读 GOAL 日志（c1/c2 两轮 + 转入 c3 遗留五条）、README、cli/paths/fingerprint/reverseip/
  icp/netutil-urlcheck/digest/parity 全文与暂存 diff → 亲手重跑全套验收 → 在本机 mock 靶站上
  fingerprint / paths / api 三模块双引擎并排实测（真实 CLI 二进制，产物逐文件比对）→ 对 fix3 与
  REVIEW-c2 六条发现逐条闭环核验（活体探针 + 定向测试）
- 本文所有数字与结论均为复核员本会话亲手执行/亲读所得，命令与出处逐条括注。

---

## 1. 验收套件亲手重跑（复核员本机实跑）

环境：go1.24.1 windows/amd64（`C:/Go/go/bin/go.exe version`）、Python 3.8.6 在 PATH，`CI` 环境变量为空。

| 命令 | 结果 |
|---|---|
| `go build -o recon-go-c3review.exe ./cmd/recon-go` | **rc=0** |
| `go build -o recon-go-c3review-root.exe .`（根兼容入口） | **rc=0** |
| `go vet ./...` | **rc=0，零告警** |
| `go test -count=1 ./...` | **15 个测试包全 ok，0 FAIL**（apiunauth 2.1s / asset 1.0s / cli 1.7s / fingerprint 0.9s / icp 1.3s / mockweb 2.7s / netutil 2.4s / **parity 49.4s** / paths 1.8s / poc 1.3s / **redteam_adv2 7.1s** / report 1.2s / reverseip 1.4s / subdomain 1.9s / toolrun 2.1s；root、cmd/recon-go、jsonx 三处 [no test files]） |
| `go test -count=1 -v ./internal/parity/` | **14/14 PASS、0 SKIP**（ParseICP/ParseHackerTarget/Classify/PocMatch/RenderMD/PathsAndAPIFullChain 35.8s 两引擎全链路/AssetParsers/PackEvidence/Baseline/Fetch/Fingerprint/HTTPProbe/VerifySubs/OneForAll） |
| `python -m unittest discover -s tests`（Python 侧回归） | **Ran 73 tests, FAILED (failures=3)**，失败名单 = `test_verify_and_evidence.TestVerifySubs` 三例（test_dns_lookup / test_run_verify_writes_outputs / test_verify_subs_marks_alive）——与 c1/c2 基线完全相同的 fake-ip 环境性失败，**fix3 无新增 Python 回归** |

- `-race` 未执行：本机无 gcc（同 REVIEW-c1 D2 / REVIEW-c2，不可行项未复跑）。
- `-count=1` 禁用缓存，parity 49.4s 与 redteam_adv2 7.1s 的耗时佐证 Python 探针与对抗场景真跑。

## 2. 计划兑现逐文件核对

### 2.1 GOAL c1/c2 交付面（承接 REVIEW-c2 §2，本轮抽样重验未发现回退）

GOAL 日志 c1 四笔 + c2 三笔提交的全部文件在本轮工作树中均在位且被测试覆盖（15 包全绿）。
复核员本轮亲读重验的锚点：`internal/fingerprint/fingerprint.go:31-60` 28 条规则与
`src/modules/fingerprint.py:15-48` **逐字一致**（name/where/pattern/type 四键逐条对照，含
「body 只认技术特征」注释语义）；`internal/paths/paths.go:15-21` PathsList 19 条与 paths.py 逐条全等；
`internal/cli/cli.go:49-53` knownCmds 14 子命令；`go.mod` 唯一第三方依赖 yaml.v3。无虚报交付。

### 2.2 GOAL「遗留（转入 c3）」五条逐条核对

| # | 遗留项 | 核对证据 | 判定 |
|---|---|---|---|
| 1 | `all` 串联、jsintel/portscan 移植拍板 + README 收口 | **拍板=维持不实现**：`cli.go:330-339`（all/jsintel/portscan → exit 2，指路 `python src/recon.py`）、helpText `cli.go:31/38/39`、README:32/38/39 三处一致。复核员真实二进制实测：`all`→rc=2、`jsintel`→rc=2、`portscan`→rc=2（本会话亲手跑）。README 状态表已收口（c1/c2 ✅行 + c3 ❌/⏸ 行 + llm 弃用声明） | ✅ |
| 2 | paths.go:14 注释「18 条」→「19 条」 | `paths.go:14` 现为「PathsList 19 条逐字对照 paths.py:20-26」，实数 19（亲数） | ✅ |
| 3 | subfinder 二进制部署 | `tools/bin` 仍不存在（本轮 `ls` 实证）；适配层「存在才用」语义不变（README:162-172），顺延遗留 | ⏸ 顺延 |
| 4 | go-engine-ci push 后确认绿 | **未核（工具缺席）**：`gh` 不在本机 PATH（`gh run list` → command not found）。工作流文件本体亲读无碍（.github/workflows/go-engine-ci.yml：windows-latest、build/vet/test -v + 环境取证步）。CI 是否绿属「未能验证」而非「已验证绿」 | ⚠️ 未核 |
| 5 | 在途改动对齐 | fix2 已入库（108ce88）；当前 staged 20 文件为 fix3（下一节），与本轮复核对象一致 | ✅ |

### 2.3 staged fix3（第 3 轮审计修复）逐项核对

| 审计项 | 代码证据（亲读） | 独立验证 |
|---|---|---|
| high#1 基线探针逐跳校验（30x 落点进基线指纹 = 内网 oracle） | `baseline.go:66-79`：Baseline 增 `hop` 参数，两次探针 Fetch 带 `HopCheck: hop`；`apiunauth.go`/`paths.go:41-42` 调用点传 `HopPolicy(base)` | `TestBaselineKinds`/`TestBaselineUnknownMarshalTwoKeys` 绿（本轮 -v 定向复跑） |
| medium#2 fingerprint 逐跳策略统一 | `fingerprint.go:109-117`：固定 `allowPrivate=true` 回调改为 `netutil.HopPolicy(url)`（公网入口 302 拒私网落点） | 套件绿；语义与 api/paths/poc 对齐亲读确认 |
| medium#3 Attempt null 语义（请求失败时 0/"" → null） | `baseline.go:114-138`：Attempt 加 ok 标记 + MarshalJSON 失败时渲染三键 null；`apiunauth.go` SaveEvidence meta 用 statusOrNil/sizeOrNil/digestOrNil | TestParityPathsAndAPIFullChain 绿（含 null 分支）；§3-M3 meta.json recheck 双侧全等 |
| medium#4 写盘失败上抛（此前吞错 exit 0 被桌面壳标「完成」） | `subdomain.go:205-212`、`apiunauth.go:327-331`、`paths.go:89-94`、`cli.go:131/270/291/326` 四处：SafeWrite 失败 → error → CLI exit 1 + fail 事件 | **活体探针**：预置 `out/<target>/paths.json` 为目录逼写盘失败 → **rc=1** + 事件序 `pipeline_start/start/fail(exit 1)/pipeline_end(fail)`（本会话实跑）。无专项单测固化（见 §5-N6） |
| low#5 FOFA/Hunter follow 对齐 | `asset.go:67-72,96-101`：Fetch 补 `Follow:true`（对齐 Python 默认跟随） | 套件绿 |
| low#6 CLI help 契约 | `cli.go:81-88`（help 子命令移出白名单→未知 exit 2）、`cli.go:425-439`（子命令 -h → 用法 + exit 0）、`progress.go:67`（`--progress_file` 下划线别名移除） | **活体探针**：`help`→rc=2（双引擎一致）、`paths -h`→rc=0（双引擎一致） |
| low#7 repro.md attempts 渲染 + 基线 None 渲染 | `apiunauth.go:100-116`（reproAttemptsJSON）、`apiunauth.go` Probe 的 blStatus nil 分支 | §3-M3：Go 现渲染 JSON 形态，数据与 Python 全等（详 §5-N2） |
| low#8 非法 URL 错误脱敏（不回显 query） | `urlcheck.go:78-86`（`?…` 截断）+ `src/modules/netutil.py:87-93,115`（`_redact_url` 同步） | 双侧亲读确认；错误分支无单测（畸形 URL Parse 失败难构，接受） |

## 3. Go/Python 并排语义对照（复核员自建 mock 场景实测，真实 CLI 二进制）

靶站双开（复核员亲手启动、复核后已杀进程）：仓库正牌 `tests/mock_server.py`（127.0.0.1:8799）+
**复核员自建指纹靶站**（127.0.0.1:8801，一页混入 8 条规则特征 + 1 个自然语言诱饵「本课讲解
ThinkPHP 框架的用法」）。Go 从 `recon-go-c3review.exe`（HEAD+fix3 工作树构建）、Python 从
`python src/recon.py` 独立 CWD 运行，产物互不污染。

### M1 fingerprint（自建靶站 8801）——c1 模块 + c3 误报回归

- 双引擎均 **9 命中且名单逐字相同**：ThinkPHP、Shiro、WordPress、Nginx、Vue、Spring Boot、
  Jenkins、Elasticsearch、Swagger UI（顺序亦同）。
- `fingerprint.json` 剥 `\r` 后 **diff 为空（逐字节全等）**。
- 自然语言诱饵（正文出现「ThinkPHP」）未触发 body 误报——82aeef1 声称的「自然语言误报回归 2 例」
  语义在真实双引擎对打中复现成立。

### M2 paths（仓库 mock /real 与 /soft404 双场景）

- **/real 存活 5 条全等**（含 size/verdict/复验结论）：`/robots.txt` `/.env` `/swagger-ui.html`
  `/actuator` `/actuator/env`；基线均判 normal(404, 29B)，baseline digest 双侧同为
  `4ae437f84d93257e`（截断后哈希口径一致）。
- **/soft404 零误报**：双侧均存活 0、过滤 19（catch-all 语义一致）。
- 产物 diff 余下差异三项，全部可解释：① 基线探针随机串 final_url（每次运行随机，非引擎差异）；
  ② **空列表形态：Go `alive:null`/`notes:null` vs Python `[]`——REVIEW-c2 F3 未修的活体实证**（§5-N1）；
  ③ **顶层键序：Go map 字母序 vs Python dict 插入序**（PARITY.md ④ 已备案为已知口径差异）。

### M3 api（仓库 mock /real，含取证三件套）

- 双引擎均 `5 命中 / 5 存活复验通过 / catch-all 过滤 0`；`api_unauth.json` 归一
  （evidence_dir 换 `<OUT>` + 随机探针串）后**语义全等**——命中行 digest 逐条相等
  （如 swagger `aa8bd468984d5ba7`、actuator/env `07535e47d92c8bde`）。
- **证据目录树 15 文件双引擎全等**；`meta.json` 十二键与 `recheck` 内容全等。
- `response.snippet.txt` 差异仅两处、均为已备案口径：采集时间戳（两次运行相差 4s）+ 行尾
  （Python CRLF / Go LF，README 已知微差 #4）；剥 `\r` 后内容逐字相同。
- **repro.md「存活复验」行（REVIEW-c2 F2 修复点）**：Go 已从 `%v` 结构体形态
  （`[{200 144 07…}]`）改为 JSON（`[{"status":200,"size":144,"digest":"07…"}]`），数据与
  Python 完全一致；Python 侧保持 repr 字面（`[{'status': 200, …}]`）——**数据全等、字面形态
  仍有 repr/JSON 微差**（§5-N2）。

三模块、七场景（fp 页 / real / soft404 + 取证链）双引擎对打：**判定流水线零漂移**。

## 4. 审计与对抗问题真修复抽查

| 宣称 | 复核方式与证据 | 判定 |
|---|---|---|
| redteam-adv2 对抗包（fix2 落定，c3 维持有效） | `go test -v ./internal/redteam_adv2/` → 4/4 PASS：TestICPKeyExfilViaRedirect（凭据防 302 外送）/ TestICPDomainQueryInjection（query 注入编码）/ TestCheckHTTPURLBlocksIntranetLanding（内网落点阻断）/ TestICPFailureLogNoKey（失败日志零 key，6.0s 真跑重试链） | ✅ |
| fix1 digest 迁移（CWE-327）持续有效 | `digest.go:14` 实读 = `sha256.Sum256` hex 前 16 位；M2/M3 双引擎 digest 逐条相等实证口径一致 | ✅ |
| fix2 ONEFORALL_HOME 清洗持续有效 | `go test -run TestRunOneForAll -v ./internal/toolrun/` → RejectsTraversalHome / MissingHome 双绿 | ✅ |
| fix2 ICP 限频假 200 防御持续有效 | `TestParseICPGolden` 绿（含「查询失败」回归用例）；`TestIPBlockedMatchesPython` 绿（0.54s 动态 python 探针真跑） | ✅ |
| fix3 medium#4 写盘失败上抛 | §2.3 活体探针（目录影子法）：rc=1 + fail 事件齐全 | ✅（缺专项单测，§5-N6） |
| fix3 low#6 help 契约 | §2.3 活体探针：`help`→2、子命令 `-h`→0，双引擎一致 | ✅ |
| fix3 low#7/medium#3 | §3-M3 repro.md/meta.json 实证 | ✅（附 N2 字面形态微差） |
| REVIEW-c2 F4（ParseICP 错误文案漂移） | 代码已修：`icp.go:35/40` 与 `icp.py:29/31` 文案一致（「响应非 JSON」/「响应格式异常」）；复核员实跑 `python -c parse_icp`：`[1,2,3]`→响应格式异常、`null`→响应格式异常，与 Go default 分支一致 | ✅ 代码闭环（测试缺口见 §5-N4） |
| REVIEW-c2 F1（HopPolicy「全部接线」表述 + 3 处盲区） | **未闭环**：`reverseip.go:86`、`subdomain.go:58/94`（crt.sh/certspotter）仍 `Follow:true` 无 HopCheck；README 已知微差 #5 仍写「Go 全部 Follow 调用点」 | ❌ 未闭环 |
| REVIEW-c2 F3（空列表 null vs []） | **未闭环**：`paths.go:49` 仍 nil slice；M2 活体实证 `alive:null` | ❌ 未闭环 |
| REVIEW-c2 R2（reverseip「等价」措辞） | **未闭环**：`reverseip.go:3-6` 仍称「等价性由黄金用例与 parity 钉死」（实为收紧语义） | ❌ 未闭环 |
| REVIEW-c2 D1（进度事件契约） | **未闭环**：活体复证 `verify`（缺 -d）：Go 4 事件 vs Python **无文件（0 事件）**，rc 均 2；`llm`：Go 4 事件 vs Python 0（Python 侧 llm 子解析器仍要求 -d，缺参在 argparse 阶段退出） | ❌ 未闭环 |

## 5. 本轮新发现（均不阻断）

- **N1（低·F3 延续）**：paths.json 空列表 Go `null` vs Python `[]`（M2 活体证据）；api_unauth.json
  `hits/all` 空时同理。fix1 已为 subdomains_live 修过同类，此处仍漏。建议 fix4 用
  `make([]T,0)` 或 MarshalJSON 兜底，双侧一并固化单测。
- **N2（低·F2 残留）**：repro.md 复验行 Go=JSON / Python=repr 字面（数据全等）。README 已知微差
  清单未备案该形态差；建议备案或双侧统一 JSON。
- **N3（低·测试缺口）**：F4 修复未补测试——`TestParseICPGolden` 覆盖 nil 但未覆盖 `[1,2,3]`
  数组 payload 与「响应格式异常」msg 文案断言；parity ParseICP 黄金集四例同样未含。行为正确
  （§4 实证），仅防回退面缺失。
- **N4（低·测试缺口）**：fix3 medium#4（写盘失败 exit 1 + fail 事件）无专项单测，本复核以目录
  影子探针实证行为正确；建议把该探针固化为 `TestWriteFailureExitOne`。
- **N5（信息·门禁定位）**：`parity.go:33-41` CI=true 时 14 项 parity 全部自跳——CI 绿只证
  「可移植核心」，跨引擎黄金对照降级为**本地人工门禁**。PARITY.md ① 有明文定位声明，纪律上
  可接受；但编排方须知：go-engine-ci 绿 **不能替代**本地 `go test ./internal/parity/`。
- **N6（琐碎·文档漂移 ×3）**：① `netutil_test.go:180` 注释仍写「<3.9 跳过」而 :221 代码门已
  `<3.11`（30ee014 只改了代码与 :217-219 注释）；② PARITY.md ④ 处置列同写「<3.9」；
  ③ README「与 Python 版的已知微差」清单编号乱（1-10 之后又出现两个 7、8）。
- **N7（信息·键序）**：paths.json/api_unauth.json 顶层键序 Go 字母序 vs Python 插入序——PARITY.md
  ④ 已备案（「差异=键序+随机探针串 final_url」），本轮 M2/M3 实证与备案一致，无需处置。

## 6. 流程记录

- **P1（红线核查）**：本轮全部验证流量仅达 `127.0.0.1:8799/8801` 两个本机 mock 靶站与本地
  python 子进程；未触碰任何真实目标（运维者自有域名与服务器 IP 已脱敏）；`go test` 全程零外网（Mimosa
  深扫未运行，本复核不涉及）。
- **P2（计划正本缺口，延续 REVIEW-c2 P2）**：GOAL 日志仍止于 c2 轮，无 c3 轮日志与验收线声明
  （dcfc220/82aeef1/3eb2c9e/30ee014/8b9717f 五笔 c3 提交未回写 GOAL）。本轮以 c2 遗留清单 +
  c3 提交信息 + README/PARITY/TEST-PORT 为对照正本。建议编排方随 fix3 提交一并补写 c3 轮日志。
- **P3（复核基准）**：staged 未提交 20 文件 = fix3（audit high#1、medium#2/3/4、low#5/6/7/8 +
  测试适配 + `src/modules/netutil.py` 同步）。本文 §1 验收与 §3 对照均对该工作树状态作出；
  提交时建议 CI 复跑（go-engine-ci.yml 路径触发 engine-go/** 应覆盖）。
- **P4（清场记录）**：临时产物全部位于 `%TEMP%/c3rev/`（未写入仓库）；`internal/` 下无任何探针
  目录（本轮双引擎对照全部走公开 CLI，零仓库内临时包）；构建产物 recon-go-c3review*.exe 已删除；
  两个 mock 靶站进程已按 PID 终止（8799/8801 复核为 down）；`git status` 仅余复核开始前即存在的
  20 项 staged fix3，无新增未跟踪文件。本轮唯一新增 = 本文档。
- **P5（不可行项）**：`gh` 不在 PATH → go-engine-ci 运行记录未能核查（§2.2-#4 如实记「未核」）；
  `-race` 无 gcc 未跑（三连同例）。

## 7. 复核结论

**第 3 轮（c3，含 staged fix3）验收通过。** 依据：

1. 验收套件复核员亲手复跑全绿（build 双入口 rc=0、vet 零告警、15 包 ok、parity 14/14 PASS 0 SKIP
   真跑 Python、redteam_adv2 4/4 PASS）；Python 侧 73 项仅剩既知 3 项 fake-ip 环境失败，无新增回归。
2. GOAL「转入 c3」五条遗留：拍板（all/jsintel/portscan exit 2，真实二进制实测）、注释勘误、
   README 收口三项兑现；subfinder 部署顺延（适配层语义不变）；CI 绿因 gh 缺席**未核**（如实记录）。
3. 三模块双引擎并排实测（fingerprint 自建靶站 / paths 双场景 / api 全链路取证）：命中名单、digest、
   证据树 15 文件、meta.json 全等；fingerprint.json 逐字节全等；判定流水线零漂移。
4. fix3 八项审计修复逐项核对，四项有活体/定向实证（medium#4 写盘失败 exit 1 + fail 事件、
   low#6 help 契约、low#7/medium#3 渲染与 null 语义），其余代码+套件证据在位。
5. REVIEW-c2 六条发现：F4 闭环（附测试缺口 N3）、F2 半闭环（数据全等、字面形态差未备案 N2）；
   **F1/F3/R2/D1 四条未闭环**（均已逐条给出活体证据与代码行号），与 6 条新发现（N1-N7）一并
   留 fix4/c4 处置，均不阻断本轮验收。

复核员声明：未修改任何生产代码；临时靶站与构建产物已清场（git status 无残留）。
