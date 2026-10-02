# PARITY.md —— Python↔Go 双引擎 parity 对照（c3 收口）

> 基线：HEAD `108ce88`（fix2 落定后）。本文所有数字来自本轮实跑（2026-10-02），
> 证据文件在 `engine-go/docs/parity-samples/`。引用历史口径处均注明。

## ① 方法论

1. **同一靶站对打**：两引擎打**同一个 Go httptest 靶站**（`engine-go/internal/mockweb`，
   与 `tests/mock_server.py` 逐字节对齐并有漂移守卫测试）。严禁各打各的 mock——
   Python BaseHTTPRequestHandler 自带 `Server:` 头、Go httptest 无，各打各的会污染 header 类断言。
2. **python -c 探针**：Go 测试内通过 `python -c` 调 `modules.netutil / modules.subdomain /
   modules.icp / modules.reverse_ip / modules.api_unauth / modules.poc_engine / modules.report`，
   环境固定 `PYTHONUTF8=1`、`PYTHONPATH=src`、cwd=仓库根（`internal/parity/parity.go:RunPy`）。
3. **python 缺失即 Skip**：`RequiresPython(t)` 探测 PATH 无 python 时 `t.Skip`——纯 Go 测试不受影响（铁律）。
4. **只比解析后结构与 strip('\r') 文本**：Python 在 Windows 写 CRLF、Go 写 LF；
   JSON 键序两侧不保证一致（Python dict 插入序 vs Go map 字母序）——一律反序列化后比对，
   文本类先 `StripCR`（`parity.go`）。
5. **不可比项显式豁免**：baseline 探针随机串（两引擎进程级各自 crypto/rand）、生成时间戳、
   zip 文件名时间戳——断言只比"结构位置"或跳过该行。

## ② parity 测试矩阵（14 项，HEAD 108ce88 全部 PASS）

| # | 测试（internal/parity/） | 断言内容 | 最近实跑 |
|---|---|---|---|
| 1 | TestParityBaseline | baseline 五场景 kind+status+sha1(digest)+size+ctype；redirect 场景 final_url 全等；其余场景 final_url 只比"停在探针 1 路径"（随机串豁免） | PASS |
| 2 | TestParityFetch | 6 条 URL（swagger/heapdump/waf/api404/empty/loginredirect）ok/status/size/sha1/ctype/body/final_url 全字段 | PASS |
| 3 | TestParityFingerprint | /real /fppage /soft404 命中序列（name+type+顺序）与 fingerprint.json 解析结果 | PASS |
| 4 | TestParityHTTPProbe | 127.0.0.1 字面量+同靶站端口：scheme/status/ctype/title/final_url（server 两侧均空） | PASS |
| 5 | TestParityVerifySubs | verify_subs(["127.0.0.1"], do_http=False) rows（host/ips/alive/http 空）——DNS 锚点用 IP 字面量，禁 NXDOMAIN 断言 | PASS |
| 6 | TestParityOneForAll | 同一 fixture（尾逗号/重复/前导点/大写/脏行）→ 同一排序子域列表（4 项） | PASS |
| 7 | TestParityParseICP | 四例黄金：filed/限频假200/400/非 JSON，比 filed+msg+icp+unit | PASS |
| 8 | TestParityParseHackerTarget | 黄金样例（大写归一/尾点/ip6.arpa/错误文案行） | PASS |
| 9 | TestParityClassify | 六例黄金（heapdump 魔数/多特征≥2/404/HTML200），body 走 stdin | PASS |
| 10 | TestParityPocMatch | _match 黄金四例（status 命中/未命中/contains/and） | PASS |
| 11 | TestParityRenderMD | 同一合成 bundle 两侧渲染 → 70 行逐行 diff（跳过"生成时间"行）；曾抓出 anyList 类型归一/数值断言两处真缺陷 | PASS |
| 12 | TestParityPathsAndAPIFullChain | 五陷阱场景（soft404/api404/waf/loginredirect/empty）两版零命中 + real 必含五端点全 live + paths 三路径全 verified（两版 CLI 全链路） | PASS |
| 13 | TestParityAssetParsers | FOFA/Hunter 解析推导式 python 内联重放 vs Go 纯函数，同 fixture 同输出（含 None→"None"） | PASS |
| 14 | TestParityPackEvidence | 两侧各打包 → arcname 集合（正斜杠规范化）+ 成员内容逐字节 | PASS |

复跑命令：`cd engine-go && C:/Go/go/bin/go.exe test -count=1 ./internal/parity/`（python 在场约 60-70s）。

## ③ mock 全场景关键输出对照表（两版 CLI 实跑，2026-10-02）

靶站：`python tests/mock_server.py 8799`（python 官方 mock，7 场景；`fppage`/`r302` 为 Go mockweb
与 redteam-adv2 自建场景，见下注）。证据：`engine-go/docs/parity-samples/mock_matrix_7scenarios.txt`。

| 场景 | api hits（py/go） | api live（py/go） | catch-all 过滤（py/go） | paths alive（py/go） | paths notes（py/go） |
|---|---|---|---|---|---|
| soft404 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| waf | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| loginredirect | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| empty | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| api404 | 0 / 0 | 0 / 0 | **1 / 1**（/metrics 命中泛化 JSON 被刷） | 0 / 0 | 19 / 19 |
| real | **5 / 5** | **5 / 5** | 0 / 0 | **5 / 5** | 0 / 0 |
| fppage* | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

- baseline kind（两版一致，实证于 TestParityBaseline 与 `tests/test_probe_integration.py:89-93`）：
  soft404→`soft404`、waf→`uniform403`、loginredirect→`redirect(302)`、empty→`normal`、api404→`soft404`。
- fingerprint（CLI 对 python mock 根路径）：real/fppage 两版均 0 命中（根路径 404，两版一致）；
  fppage 显式头+ThinkPHP 特征命中由 Go mockweb 靶站的 parity/单元测试覆盖（TestMatchFpPage：[ThinkPHP, Nginx]）。
- **r302**（redteam-adv2 自建临时靶站：soft404 壳 + 全端点真命中，验证"重定向落地后 catch-all
  过滤不误杀真命中"）：Go 版 25 个端点全命中且全存活——证据 `engine-go/docs/parity-samples/api_r302_stdout.txt`
  （同目录 fp_r302 / paths_r302 / api_direct_lan 为同轮采样）。
- **口径说明**：「mock 全流程对照」= 模块全集逐个对照（api/paths/fingerprint/baseline/verify/poc），
  **不含 `all` 一键全流程**——all 在 c3 拍板为不实现（见 README 状态表），Python 版可跑全流程作参照。
- jssite 场景属 jsintel（未移植，c3 拍板），不进对照表。

## ④ 已知口径差异清单（两轮沉淀，全部"可解释且已对齐"）

| 差异点 | 说明 | 对齐方式 |
|---|---|---|
| digest | 内容形态指纹 sha256(raw) hex 前 16 位（fix1 起，sha1 弃用） | 两引擎同步迁移，TestParityBaseline/Fetch 断言相等 |
| CRLF vs LF | Python write_text 在 Windows 产 CRLF，Go 产 LF | parity 只比 strip('\r') 文本/解析后结构 |
| 动态 JSON 键 | Go struct omitempty vs Python dict 动态键；map 键序字母序 vs 插入序 | 反序列化后按键比对，不比键序/键存在性 |
| RE2 label 改写 | reverse 正则 `(?!-)/(?<!-)` lookaround RE2 不支持 → label 校验函数 | 黄金用例+TestParityParseHackerTarget 钉死等价 |
| 时间戳 | generated_at/zip 文件名/collected_at 不可 byte 比 | clock 注入 + diff 跳时间行 + arcname 集合比 |
| baseline 探针串 | 进程级随机（token_hex(5) vs crypto/rand） | final_url 只比"探针 1 路径"后缀，redirect 场景全等 |
| 数字类型 | JSON→float64 vs Go int 字面量 | 渲染层 numOf 通用提取（c2 parity 抓出后修） |
| 子进程超时 | Python TimeoutExpired 炸穿 vs Go 告警返空走降级链 | README 差异说明（行为等价：该通道无结果） |
| 私网全集 | Go 标准库缺 Python 的私网/保留段（含 198.18.0.0/15 fake-ip 段） | 自实现全集 + 动态 python 探针单测逐 IP 钉死 |
| 私网表的 Python 版本口径 | ipaddress 私网表随 CPython 版本漂移：3.8 与 3.13 差异段 = IPv4 192.0.0.0/29(+170/31)→/24、IPv6 新增 64:ff9b:1::/48、2002::/16、3fff::/20。**Go 表统一按 3.13 口径**（与 CI runner 一致）；本机 3.8 引擎在上述 4 个极端段上更宽松（不影响 fake-ip/RFC1918/回环等核心场景） | 探针测试版本感知：python <3.9 跳过版本差异段对照（netutil:TestIPBlockedMatchesPython） |

## ⑤ 真实目标对照（xycovo.com，白名单内自有资产，人工验收 2026-10-02 20:14-20:20）

命令集（两版各跑一遍，单次无并发克制执行）：
`fingerprint -u https://xycovo.com`、`paths -u https://xycovo.com`、`api -u https://xycovo.com`、
`subdomain -d xycovo.com --verify`、`report -t xycovo.com`。

| 指标 | Python 版 | Go 版 | 一致性 |
|---|---|---|---|
| 指纹命中 | 0（无） | 0（无） | ✅ |
| paths 基线 | normal（404, 14691B） | normal（404, 14691B） | ✅ |
| paths 基线 digest | `1229a80e9158c935` | `1229a80e9158c935` | ✅ **完全相同** |
| paths alive | 1（/robots.txt, 200, 71B, 复验通过） | 1（同） | ✅ |
| api hits / 过滤 | 0 / 0 | 0 / 0 | ✅ |
| 子域数量 | 0 | 0 | ✅ |
| 子域链路 | crt.sh→私网阻断（198.18.0.178）→certspotter→阻断（198.18.0.182）→空 | 同 | ✅ |
| report | 生成，无证据跳过 zip | 同 | ✅ |
| fingerprint.json | — | — | ✅ 逐字节一致 |
| paths.json | 差异=键序+随机探针串 final_url | 同左 | ✅ 可解释（④清单第 5/6 行） |
| report.md | 差异=生成时间行 | 同左 | ✅ 可解释 |

**差异解释与合理性结论**：无实质差异。①指纹/路径/API 三模块两版输出逐项相同，基线 digest
两版对同一 14691B 的 404 页算出**同一 SHA-256 前 16 位**（真实环境佐证 digest 口径对齐）；
②子域 0 条系本机 Clash fake-ip 把 crt.sh/certspotter 解析到 198.18.0.0/15，两版 SSRF 防御
（私网全集阻断）**同样正确工作**——这不是数据源时变差异，而是防御语义 parity 的实证；
预期中的"干净静态博客"画像（软 404 基线 normal、无 API 暴露、仅 /robots.txt 可访问）两版判定一致。
47.100.49.228 本轮未测（计划不强制）。
