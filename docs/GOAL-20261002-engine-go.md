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

