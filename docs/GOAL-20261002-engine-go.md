# engine-go 移植轮次日志（2026-10-02 起）

总纲：把 src-recon-tool 的 Python 引擎（src/recon.py + src/modules/）重写为纯 Go，落 `engine-go/`，
产出单文件 `recon-go.exe`，CLI 子命令与 `python src/recon.py` 一一对齐。选择性重写：只移植引擎自身
编排逻辑；外部工具（OneForAll/vulmap/dirsearch 等）保持子进程调用；HTTP 数据源（crt.sh/certspotter/
FOFA/Hunter/备案）用 Go 原生客户端实现；subfinder 仅作子域可选补充通道；llm 模块不移植（弃用）。
红线：go test 全程零外网，真实目标实测仅限 xycovo.com / 47.100.49.228 / 本机 mock。

---

## 第 1 轮（c1）— 2026-10-02

### 目标
recon-go 骨架 + subcommand 分发 + 外部工具子进程适配层（OneForAll 主通道 / subfinder 可选通道）
+ 存活验证（--verify）+ 指纹模块 + httptest mock 基建 + Python↔Go parity 骨架。
验收线：`go build` 单 exe + `go test ./...` 全绿（含 parity，python 在场必须真跑）。

### 产出
提交（全部已推 origin/main，顶端即 c76962d）：
- `2726c7a` 引擎底座：internal/netutil（fetch/软404 基线/SSRF 边界/安全落盘）+ internal/jsonx；单测含动态 python 探针钉死 Python 3.8 私网全集
- `88373cc` internal/mockweb（httptest 靶站，与 tests/mock_server.py 逐字节对齐 + 漂移守卫）+ internal/toolrun（OneForAll 主通道 / subfinder 可选通道 + 路径纪律）
- `3c76fa0` internal/subdomain（枚举 OneForAll→crt.sh→certspotter 降级链 + DNS/HTTP 存活验证）+ internal/fingerprint（28 条规则，与 src/modules/fingerprint.py:15-48 逐条对应）+ main.go 14 子命令 CLI + internal/parity 矩阵 + README
- `c76962d` CLI 逻辑拆 internal/cli，cmd/recon-go 与根 main.go 双薄壳入口（行为等价）

规划侧（本轮前置，2026-10-02 架构师产出）：IterPlan 已定 11 项语义对齐点与 parity 矩阵；
engine-go/ 最小 go.mod+main.go sanity build 先行验证工具链（Go 1.24.1，GOPROXY=goproxy.cn,direct 已就位）。

### 语义漂移（Python→Go 已知差异与处置）
1. **私网判定全集**：Go `net.IP.IsPrivate` 仅 RFC1918，Python 3.8 `is_private` 另含
   198.18.0.0/15（恰为本机 Clash fake-ip 段）、0.0.0.0/8、192.0.0.0/29、198.51.100.0/24、
   203.0.113.0/24、240.0.0.0/4 等——netutil 自实现全集，单测 `TestIPBlockedMatchesPython`
   用动态 python 探针逐 IP 对照钉死（internal/netutil 测试 165-182 行）。
2. **DNS 序**：Python `sorted()` 对 IP 字符串是字典序（非数值序）——Go 用 `sort.Strings` 对齐。
3. **DNS 环境**：本机 Clash fake-ip 劫持使 `.invalid` 假域名解析出 198.18.0.128，NXDOMAIN
   假设不成立（Python 基线因此本机 3/65 失败：`python -m unittest discover -s tests` →
   FAILED，全在 test_verify_and_evidence.TestVerifySubs；CI runner 无 fake-ip 应绿）——
   parity 的 DNS 锚点一律用 `127.0.0.1` 字面量，禁止依赖"假域名必须解析失败"。
4. **行尾/编码**：Python `write_text` 在 Windows 产 CRLF、Go 产 LF——parity 一律比解析后
   结构与 strip('\r') 文本，禁比原始字节。
5. **HTTP 超时语义**：Python timeout 为 socket 级、Go `Client.Timeout` 为整请求级——parity
   按结构化字段不按耗时。
6. **sha1 口径**：对 max_bytes 截断后的 raw 计算再取 hex 前 16 位（先截断后哈希，顺序不可反）。
7. **4xx/5xx**：两侧语义一致均算 ok=true（Python 走 HTTPError 分支）；redirect 上限两侧默认 10。
8. **header 形态**：多值头按 `k: v` 逐行小写序列化作指纹 haystack；两引擎打同一 Go httptest
   靶站，规避 BaseHTTPRequestHandler 自带 Server 头的污染。
9. **可测性增强（语义不变）**：crt.sh/certspotter URL 做成包级 var 注入，测试打 httptest stub；
   指纹 fixture 页 /fppage 用受控显式头。
10. **勘误**：架构师 IterPlan 里写"指纹 25 条规则"系笔误，实为 28 条（fingerprint.py:15-48 实数），
    施工按源码 28 条移植（commit 3c76fa0 同为 28）。

### 审计对抗处置
- **SSRF 边界**：CheckHTTPURL 对齐 netutil.py:77-111——scheme 白名单 + 私网/环回/链路本地/
  保留段默认阻断，allow_private 必须显式传（放行是显式决定，不做静默默认）。
- **目录穿越**：safeio 收口（SafeFilename 白名单 `[A-Za-z0-9._-]`→`_` 截 64 / SafeOutdir 剔
  `..` / SafeWrite+commonpath 越界校验），对齐 netutil.py:69-163。
- **零外网测试**：go test 全程 httptest stub + fixture（OneForAll fixture 以
  testdata/oneforall_fake.py.txt 入库、运行时拷贝改名执行，兼容 Mimosa 写盘纪律）。
- **mock 漂移守卫**：mockweb 的场景响应体与 tests/mock_server.py 常量逐字节比对，防两边靶站走样。
- **路径纪律**：toolrun 探测 `tools/bin/subfinder.exe` → PATH，缺席即跳过（可选通道语义）。
- **实测白名单**：本轮自动化测试零真实目标请求；xycovo.com / 47.100.49.228 仅留人工验收。

### 复核结论（本轮实跑，c76962d 独立 worktree，避开工作区在途 r2/fix1 改动）
- `C:/Go/go/bin/go.exe build -o recon-go.exe .` → BUILD OK，单 exe 9,451,520 bytes
- `go vet ./...` → 干净
- `go test ./...` → 6 个测试包全 ok（fingerprint/mockweb/netutil/parity/subdomain/toolrun）
- `go test ./internal/parity/ -v` → **6/6 PASS、0 SKIP**：TestParityBaseline / TestParityFetch /
  TestParityFingerprint / TestParityHTTPProbe / TestParityVerifySubs / TestParityOneForAll
  （parity 11.6s ≈ python 探针真跑，非静默跳过）
- CLI 面：internal/cli/cli.go 实测 grep 到全部 14 个子命令（与 recon.py:137-212 对齐）
- llm 弃用声明：engine-go/README.md:41、114-118（`recon-go llm` 打印弃用提示并 exit 2）
- 推送：origin/main 顶端 = c76962d，4 个 c1 提交全部在远端

### 遗留（转入 c2/c3）
1. 未移植子命令（c2/c3）：all 串联 / asset / reverse / icp / paths / api（27 端点清单 + 取证
   模式）/ jsintel / portscan / poc（YAML 引擎）/ report（资产档案 + 证据包）。jsintel/portscan
   是否纳入移植需拍板（源码已在仓：ac27f1e/6560c26/9ee0a48，且 origin/main 已含）。
2. subfinder 二进制未部署（tools/bin 不存在）：适配层已就绪，下载走 gh-proxy 属 best-effort，
   版本记录待首次部署时落 tools/bin/VERSIONS。
3. Go CI 不加（铁律本轮不动 CI）；tests.yml 只护 Python 不受影响（已核实无 paths 过滤冲突）。
4. Python 侧本机 3 项 fake-ip 环境性失败：非本轮范围，待本机 DNS 环境修复后自愈。
5. API 27 端点清单、软404 基线在 api/paths 场景的矩阵、证据包结构（meta.json/response.snippet.txt/
   repro.md）语义确认点，c2/c3 动工前需按 api_unauth.py/report.py 现状再切一轮 IterPlan。

---

## 第 2 轮（c2）— 2026-10-02

### 目标
全模块对齐：asset（FOFA/Hunter 原生客户端，key 走环境变量）/reverse（IP 反查）/icp（备案）/
paths（软 404 基线逐条对照）/api（27 端点清单+取证模式）/poc（YAML 引擎）/report（资产档案+证据包
zip）；CLI 七子命令从"未实现"拆出真实现；验收=go build 单 exe + go vet + go test ./... 全绿（含 c2 parity）。

### 产出
提交（均已推 origin/main）：
- `6e0c58d` **engine-go(fix1)**：第 1 轮审计修复落定——digest 迁移（sha1→sha256 前 16 hex）/safeio
  Windows 保留名/verify 与 cli 修复+parity；GOAL 日志与 c1 审计件入库（代在途会话提交；Python+Go
  测试仅剩既知 3 项 fake-ip 环境失败）。c2 叠加其上，前置条件满足。
- `af5bf7d` **engine-go(c2)**：七模块真实现——internal/asset（FOFA/Hunter）/internal/reverseip（RE2
  域名校验改写）/internal/icp（限频假 200 防御）/internal/paths（基线+复验）/internal/apiunauth（27
  端点+取证三件套）/internal/poc（yaml.v3）/internal/report（档案+证据包）；cli 七子命令拆出真实现
- `398ca9e` **engine-go(c2)**：c2 parity 矩阵——parse_icp/parse_hackertarget/classify/poc_match 黄金
  四套 + render_md 逐行 diff + paths/api 全链路同靶站 + 证据包 arcname/成员 + FOFA/Hunter 解析层
  内联重放；README 状态表同步
- 相邻轮次（非 engine-go 范围，如实记录）：`7aa31bd`/`4853fc5` desktop-go(c2) 两笔、`189f4ca`
  ci: Go engine+desktop 双构建双测试工作流（**新增 .github/workflows/go-engine-ci.yml**，
  paths 触发 engine-go/**、desktop-go/**，working-directory=engine-go）

### 语义漂移（Python→Go 已知差异与处置）
1. **digest 口径**（fix1 起）：fetch 返回 `digest=sha256(raw) hex 前 16 位`，替代 sha1——
   engine-go/internal/netutil/digest.go:16 与 Python 同步迁移；c2 的 api row/meta、取证 snippet
   全部 digest 口径（apiunauth.go:113/177/186 实证）。
2. **reverse 域名正则**：Python `^(?!-)…(?<!-)(\.…)+$` 含 lookaround，RE2 不支持——改写为
   label 校验函数（reverseip.go:4,25-32：每段 1-63 字符、仅 [a-z0-9-]、首尾非 -、≥2 段），
   黄金用例（大写归一/尾点/ip6.arpa/含空格行/错误文案行）钉死等价性。
3. **safe_filename Windows 保留设备名**（fix1）：con/prn/aux/nul/com1-9/lpt1-9 主干命中补 `_`，
   Python（netutil.py）与 Go（safeio.go）同步。
4. **paths 字典条数勘误**：两轮 IterPlan 均误写"18 条"，实测 `python -c "…print(len(PATHS))"`
   → **19**；Go PathsList 实数 19 条与 Python 全等（仅 paths.go:14 注释文案误写 18，行为无差，
   c3 顺手修注释）。
5. **动态 JSON 键**：paths Row 的 verdict/verified/recheck 用 omitempty 对齐 Python dict
  「有值才出现」的动态键行为（paths.go:18-33）。
6. **FOFA/Hunter 私网阻断与 mock 冲突**：asset.py check_http_url 默认 allow_private=False，
   而测试 mock 在 127.0.0.1——解析层（ParseFofaResults/ParseHunterArr 纯函数）与 HTTP 层分离，
   Python parity 在解析层内联重放推导式，不强行全链路对打。
7. **report 时间依赖**：generated_at/zip 文件名时间戳使 byte 级 parity 不可行——render_md parity
   逐行 diff 跳过时间行；pack_evidence parity 断言 arcname 集合+成员内容。
8. **首个第三方依赖**：gopkg.in/yaml.v3 v3.0.1（POC YAML 引擎；经 goproxy.cn 实测可拉，仓库唯一
   非 stdlib 依赖）。
9. **Python 侧 llm 模块已整体移除**（README.md:41：两侧行为一致——提示并 exit 2）。

### 审计对抗处置
- **四陷阱零误报**：soft404/api404/waf/loginredirect 四场景 api+paths 必须 0 命中，
  TestProbeNoFalsePositives 固化（test_probe_integration.py 语义对齐移植）。
- **真阳性不漏报**：real 场景必含 swagger-ui.html/v3/api-docs/actuator/actuator env/actuator
  heapdump 且全部存活复验通过。
- **ICP 限频假 200 防御**：code=200 但值「查询失败」→filed=false（icp 黄金用例含此回归）。
- **证据包安全**：arcname 相对 out/ 且不得穿越（report.go:430-432 filepath.Rel+纵深跳过）；
  report.md 不内联敏感值；save_evidence host/slug 白名单防目录穿越（TestSaveEvidencePathSafety）。
- **27 端点表防篡改**：len==27 硬断言（apiunauth_test.go:17）+ 与 Python 全等在 parity；
  heapdump 需 JAVA PROFILE 魔数、多特征端点需 ≥2 命中（classify 黄金六例）。
- **零外网红线**：FOFA/Hunter/apihz/hackertarget 全部 URL var 注入打 httptest stub。

### 复核结论（本轮实跑，398ca9e 独立 worktree，避开工作区在途 r3 改动）
- `go build -o recon-go.exe .` → BUILD OK，单 exe 10,265,600 bytes；`go vet ./...` 干净
- `go test ./...` → 15 个测试包全 ok（含 asset/cli/icp/paths/poc/report/reverseip/apiunauth 新包；
  apiunauth 行首次被 tail 截去，补跑 `go test ./internal/apiunauth/ -v` → 6/6 PASS：
  EndpointsTableSane/ClassifyGolden/ProbeNoFalsePositives/ProbeRealDetectedAndLive/
  RunAPIWritesDocAndEvidence/SaveEvidencePathSafety）
- `go test ./internal/parity/ -v` → **14/14 PASS、0 SKIP**，c2 新增 8 项：ParseICP/ParseHackerTarget/
  Classify/PocMatch/RenderMD/PathsAndAPIFullChain（35.8s 两引擎全链路）/AssetParsers/PackEvidence
- CLI：cli.go:182-290 七子命令真实现（带 recon.py 行号对照注释），:310 all/jsintel/portscan
  维持未实现 exit 2
- README 状态表（:29-41）：c1/c2 逐子命令标注、c3 待办、llm 弃用声明
- Python 侧回归：`python -m unittest discover -s tests` → Ran 73 tests, FAILED (failures=3)，
  失败名单与 c1 基线完全相同（test_verify_and_evidence.TestVerifySubs 三例，Clash fake-ip 环境
  性），fix1+c2 无新增 Python 回归
- paths 字典全等：Python len(PATHS)=19（实跑），Go PathsList=19（实数），逐条一致

### 遗留（转入 c3）
1. `all` 串联（域名/IP 双输入全流程编排）、jsintel/portscan 移植拍板（两模块现已在 GitHub，
   ac27f1e/6560c26/9ee0a48）、README 状态表收口。
2. paths.go:14 注释"18 条"改"19 条"（文案勘误，行为无差）。
3. subfinder 二进制仍未部署（tools/bin 不存在，适配层 c1 已就绪）；c3 若部署走 gh-proxy 并记录版本。
4. go-engine-ci.yml 已上线（189f4ca）——超出"Go CI 本轮不加"的原纪律，为后续会话所加；
   c3 push 后需 `gh run list` 确认 Go CI 亦绿（CI 不过不算完成的纪律现在同时约束两侧）。
5. 工作区已有第 3 轮在途改动（apiunauth/asset M、redteam_adv2 新包、stdout 采样文件）——c3 动工
   前先对齐在途会话进度，勿重复施工。

---

## 第 3 轮（c3，收口轮）— 2026-10-02/03

### 目标
parity 全量跑通并落 docs/PARITY.md（mock 全场景 Python vs Go 关键输出对照表）；
docs/TEST-PORT.md 测试平移全量清点表；白名单内 xycovo.com 真实小规模侦察两版合理性对比；
README 更新（Go 版用法/llm 弃用/状态表收口）；commit + push。

### 产出
提交（六笔，全部已推 origin/main，`git status -sb` 无 ahead）：
- `108ce88` **engine-go(fix2)**：第 2 轮审计修复 + redteam-adv2 只读对抗测试包落定（r302 场景/
  限频防御/safeio 加固 + fix2 测试；src 侧 icp/report/recon 同步）；4 个 CLI stdout 采样收编
  `engine-go/docs/parity-samples/` 作 PARITY 证据；GOAL 第 2 轮节与 REVIEW-c2 入库（代在途会话提交）
- `dcfc220` **PARITY.md 五节对照**（方法论/14 项矩阵/mock 七场景两版 CLI 采样表/口径差异清单/
  xycovo.com 真实对比）+ **TEST-PORT.md 平移清点**（Python 73→Go 127 实测口径）
- `82aeef1` 收口拍板：all/jsintel/portscan **维持不实现**（cli helpText :37-38 + dispatch :323-324
  "c3 拍板（终态）" + 双 README 文案一致，均指 Python 版）；补 fingerprint 自然语言误报回归 2 例
  （test_new_modules.py:114-129 平移缺口）
- `3eb2c9e` / `30ee014` go-engine-ci 红灯修复：私网全集表升级 CPython 3.13 口径 + 探针测试版本感知；
- `8b9717f` parity 定位收口为**本地黄金对照门禁**——RequiresPython 加 CI 环境自跳（CI 只跑可移植
  核心），go-engine-ci 加环境取证步 + go test -v 留档

### 语义漂移（第 3 轮新增）
1. **私网全集表的 CPython 版本口径**：CI 红灯暴露——64:ff9b:1::/48、2002::/16、3fff::/20 与
   192.0.0.0/29→/24 是 CPython 3.13 才入 ipaddress 的段；本机 Python 3.8/3.12 与 runner 3.9/3.10
   均不含。Go 侧升级为 3.13 口径，动态 python 探针改版本感知（<3.11 跳过版本差异段）——
   "对齐 Python"从对齐某一版本改为对齐最新口径+显式版本感知（PARITY.md ④）。
2. **parity 门禁定位调整**：CI 环境 python 版本不可控（3.9 无私网表）→ RequiresPython 在 CI 自跳，
   parity 全量矩阵定位为本地黄金对照门禁（本机 3.12/3.13 全量 15 包复现全绿，30ee014）。
3. **真实环境 fake-ip 事实**：xycovo.com 实测子域 0 条——Clash fake-ip 把 crt.sh/certspotter 本身
   解析进 198.18.0.0/15，两版 SSRF 防御同样阻断。这是防御语义 parity 的实证而非数据源差异
   （PARITY.md ⑤差异解释）。
4. **digest 真实环境佐证**：xycovo.com 的 14691B 404 页，两版独立算出同一 SHA-256 前 16 位
   `1229a80e9158c935`——digest 口径对齐在真实目标上闭环。
5. llm 弃用终态：Python 侧 llm_assist.py 已删除、recon.py:260-262 子命令提示弃用 exit 2；
   Go 侧 cli.go:177 同行为——"不移植"收敛为"两侧一致弃用"。

### 审计对抗处置
- redteam-adv2 只读对抗测试包落定（假 key 声明/黑洞端口/httptest 零外网，redteam_adv2 4 项测试）。
- fix2 修复面：r302 重定向场景、ICP 限频防御加固、safeio 加固 + fix2 系列回归测试。
- 指纹自然语言误报回归 2 例补齐平移缺口（"think 和 php"文章正文不再误判 ThinkPHP）。
- 证据链纪律：CLI 实跑 stdout 采样统一收编 `engine-go/docs/parity-samples/`，PARITY.md 逐表引用。

### 复核结论（本轮实跑，8b9717f 独立 worktree）
- `go build -o recon-go.exe .` → BUILD OK，单 exe 10,303,488 bytes；`go vet ./...` 干净
- `go test ./...` → **15 包 ok + 1 FAIL**：`TestRunSubfinderTimeoutAborts`
  （internal/toolrun/fix2b_test.go:31——subfinder 300ms 超时未生效，实测阻塞 3.28s，Windows 本机
  实测失败；工作区在途改动为 subdomain/fix2b_test.go，未见 toolrun 对应修复）。其余全部绿，
  含 parity 59.4s、redteam_adv2 11.6s。
- Python 侧：`python -m unittest discover -s tests` → Ran 73 tests, FAILED (failures=3)——
  既知 fake-ip 环境失败，无新增回归。
- PARITY.md 抽查（docs/PARITY.md 实读）：五节齐全；14 项矩阵带断言说明；xycovo 逐指标对比表
  指纹 0/0、paths alive 1(/robots.txt 200,71B,复验通过) 两版一致、api 0/0、差异全部标注可解释。
- TEST-PORT.md 抽查：Python 73 项 → Go 127 Test 函数/15 包（实数口径，明确"不追求数字相等、
  不凑 83"）；jsintel 15 项 + portscan 8 项标不适用；3 项环境失败标注"非平移缺口"。
- 拍板一致性 ✅：cli.go:37-38/323-324 与双 README 文案一致；TEST-PORT.md:110 详表已同步
  （:20-21 汇总表旧文案"待拍板"未同步，文案级瑕疵，见遗留）。
- **CI 状态未能本机核实**：gh 命令不存在；GitHub API 匿名查询返回 rate limit exceeded
  （2026-10-03 实测）——需人工到 GitHub Actions 页确认 tests.yml 与 go-engine-ci.yml 最新绿。

### 遗留
1. **TestRunSubfinderTimeoutAborts 失败（本轮复核发现的 c3 顶端真实缺陷）**：Windows 下
   subfinder 超时中止未按 ~300ms 生效（阻塞 3.28s）——下一轮修复优先项；修复前 subfinder 通道
   带超时不可信（可选通道，不影响 OneForAll 主链路）。
2. CI 双绿需人工确认（本机无 gh、API 限流）；go-engine-ci 的环境取证步产出可在 Actions 日志回查。
3. TEST-PORT.md:20-21 汇总表 jsintel/portscan 行仍是"待 c3 拍板"旧文案，与 :110 拍板结论不同步
   ——文案勘误。
4. 工作区又有新一批在途改动（apiunauth/asset/cli/fingerprint/netutil/subdomain fix2b_test 等 M）
   ——归属后续会话，勿在本日志范围处置。
5. **三轮 IterPlan 至此全部完成**：engine-go 与 Python 版语义对齐状态以 PARITY.md/TEST-PORT.md
   为准；后续演进（subfinder 超时修复、jsintel/portscan 若拍板移植、all 串联）另起轮次。


