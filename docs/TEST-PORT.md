# TEST-PORT.md —— Python → Go 测试平移全量清点（c3 收口）

> 口径：HEAD `108ce88` + fingerprint 补测 1 项。实测（2026-10-02）：
> **Python 73 项**（`python -m unittest discover -s tests`，9 文件；其中 3 项本机
> fake-ip 环境性失败）→ **Go 127 个 Test 函数 / 15 包**（`grep -rE "^func Test" --include="*_test.go" | wc -l`）。
> 两侧计数口径不同（unittest 方法数 vs go test 函数数），**不追求数字相等**，追求语义逐项映射。
> 指令早期提到的"83"无实数对应，本表以实测为准、不凑数。

## 汇总

| Python 测试文件 | 项数 | Go 去向 | 状态 |
|---|---|---|---|
| test_new_modules.py | 15 | netutil/reverseip/icp/apiunauth/fingerprint | ✅ 全平移（含本表补齐的指纹自然语言回归 2 例） |
| test_poc_engine.py | 4 | internal/poc | ✅ 全平移 |
| test_probe_integration.py | 9 | paths/apiunauth/netutil（mock 集成） | ✅ 全平移 |
| test_report.py | 7 | internal/report | ✅ 全平移 |
| test_verify_and_evidence.py | 7 | subdomain/apiunauth | ✅ 平移（3 项环境失败改写锚点，见下） |
| test_progress_file.py | 5 | internal/cli（progress 事件流） | ✅ 全平移（fix1） |
| test_fix1_parity.py | 3 | — | ◻ 不适用（Python 侧对 Go 行为的反向锚定，Go 即参照实现） |
| test_jsintel.py | 15 | — | ⏸ 不适用（jsintel 待 c3 拍板是否移植） |
| test_portscan.py | 8 | — | ⏸ 不适用（portscan 待 c3 拍板是否移植） |

Go 侧另有 Python 无对应的自有测试：mockweb 漂移守卫/场景（2）、parity 矩阵（14）、
toolrun 适配层（7）、asset（6）、jsonx、redteam_adv2 对抗包（4）、fix2 系列回归等——
属"Go 侧自证 + 双引擎 parity"新增面，不占平移映射。

## 逐文件映射表

### test_new_modules.py（15）→ Go

| Python 类/方法 | Go 测试 | 状态 |
|---|---|---|
| TestIPDetect.test_is_ip | cli/fix1_cli_test.go:TestIsIPNoTrim（口径差异：Python ip_address(" 1.2.3.4 ")判假，Go fix1 起去 TrimSpace 对齐） | ✅ 等价改写 |
| TestReverseParse.test_parse_hackertarget | reverseip:TestParseHackerTargetGolden | ✅ 已平移 |
| TestReverseParse.test_parse_empty | reverseip:TestParseHackerTargetGolden（同函数含空串/错误文案两断言） | ✅ 已平移 |
| TestICPParse.test_filed | icp:TestParseICPGolden | ✅ 已平移 |
| TestICPParse.test_not_filed | icp:TestParseICPGolden | ✅ 已平移 |
| TestICPParse.test_ratelimit_disguised_as_200 | icp:TestParseICPGolden（限频假 200） | ✅ 已平移 |
| TestICPParse.test_bad_payload | icp:TestParseICPGolden（非 JSON/nil） | ✅ 已平移 |
| TestApiClassify.test_swagger_hit | apiunauth:TestClassifyGolden | ✅ 已平移 |
| TestApiClassify.test_html_200_is_not_hit | apiunauth:TestClassifyGolden | ✅ 已平移 |
| TestApiClassify.test_404_not_hit | apiunauth:TestClassifyGolden | ✅ 已平移 |
| TestApiClassify.test_heapdump_requires_java_profile_magic | apiunauth:TestClassifyGolden（魔数正反两断言） | ✅ 已平移 |
| TestApiClassify.test_multi_marker_endpoint_needs_two | apiunauth:TestClassifyGolden（need=2 正反两断言） | ✅ 已平移 |
| TestApiClassify.test_endpoints_table_sane | apiunauth:TestEndpointsTableSane（len==27 + parity 全等断言） | ✅ 等价改写 |
| TestFingerprintRules.test_no_natural_language_thinkphp | fingerprint:TestNoNaturalLanguageThinkPHP（**c3 本轮补齐的缺口**） | ✅ 本轮补齐 |
| TestFingerprintRules.test_techphp_tech_marker_still_hits | fingerprint:TestNoNaturalLanguageThinkPHP（技术特征正断言） | ✅ 本轮补齐 |

### test_poc_engine.py（4）→ Go

| Python | Go | 状态 |
|---|---|---|
| TestMatcher.test_status_match | poc:TestMatchGolden | ✅ |
| TestMatcher.test_status_miss | poc:TestMatchGolden | ✅ |
| TestMatcher.test_contains_match | poc:TestMatchGolden | ✅ |
| TestMatcher.test_and_condition | poc:TestMatchGolden | ✅ |

### test_probe_integration.py（9）→ Go（mock 集成；两版对打由 parity 12 项加固）

| Python | Go | 状态 |
|---|---|---|
| test_soft404_spa_has_no_false_positives | paths:TestPathsNoFalsePositives + apiunauth:TestProbeNoFalsePositives | ✅ 已平移 |
| test_json_soft404_has_no_false_positives | 同上两测试 | ✅ 已平移 |
| test_uniform_403_waf_has_no_false_positives | 同上两测试 | ✅ 已平移 |
| test_redirect_to_login_has_no_false_positives | 同上两测试 | ✅ 已平移 |
| test_plain_404_site | 同上两测试（empty 场景） | ✅ 已平移 |
| test_real_exposures_are_detected_and_live | apiunauth:TestProbeRealDetectedAndLive | ✅ 已平移 |
| test_real_paths_are_detected | paths:TestPathsRealDetected | ✅ 已平移 |
| test_baseline_kinds | netutil:TestBaselineKinds + parity:TestParityBaseline | ✅ 已平移 |
| test_verify_live_flags_unstable | netutil:TestVerifyLive（stable/feature-lost 两例） | ✅ 等价改写 |

### test_report.py（7）→ Go

| Python | Go | 状态 |
|---|---|---|
| test_missing_outputs_do_not_crash | report:TestCollectMissingOutputsDoNotCrash | ✅ |
| test_report_does_not_inline_secrets | report:TestReportDoesNotInlineSecrets | ✅ |
| test_report_renders_jsintel_and_ports_without_full_secrets | report:TestReportDoesNotInlineSecrets（jsintel/ports 节断言合并） | ✅ 已平移 |
| test_evidence_zip_arcnames_are_relative | report:TestPackEvidenceArcnamesRelative + parity:TestParityPackEvidence | ✅ 已平移 |
| test_idempotent_regeneration | report:TestIdempotentRegeneration（行数口径，时间戳注入） | ✅ 等价改写 |
| test_poisoned_icp_record_is_not_rendered_as_real | report:TestPoisonedICPNotRendered | ✅ 已平移 |
| test_pack_returns_empty_when_no_evidence | report:TestPackEmptyWhenNoEvidence | ✅ |

### test_verify_and_evidence.py（7）→ Go

| Python | Go | 状态 |
|---|---|---|
| test_dns_lookup ⚠️本机环境失败 | subdomain:verify_test:TestDNSLookupLiteral | ✅ 等价改写（锚点 127.0.0.1 字面量） |
| test_dns_lookup_restores_default_timeout | subdomain:DNSLookup 用 context 超时，进程默认超时无污染面（结构性消除） | ✅ 等价改写（设计差异） |
| test_verify_subs_marks_alive ⚠️本机环境失败 | subdomain:TestVerifySubsOrderPreserved + parity:TestParityVerifySubs | ✅ 等价改写（锚点 127.0.0.1） |
| test_http_probe_against_mock | subdomain:TestHTTPProbeAgainstMock + parity:TestParityHTTPProbe | ✅ 已平移 |
| test_run_verify_writes_outputs ⚠️本机环境失败 | subdomain:TestRunVerifyWritesOutputs | ✅ 等价改写（锚点 127.0.0.1） |
| TestEvidence.test_evidence_written_for_live_hits | apiunauth:TestRunAPIWritesDocAndEvidence + parity:TestParityPathsAndAPIFullChain | ✅ 已平移 |
| TestEvidence.test_evidence_dir_cannot_escape_out | apiunauth:TestSaveEvidencePathSafety | ✅ 已平移 |

### test_progress_file.py（5）→ Go（fix1 已平移）

| Python | Go | 状态 |
|---|---|---|
| EmitContractTest.test_emit_writes_jsonl_contract | cli:TestProgressFileDoneContract | ✅ |
| test_emit_appends_lines_in_order | cli:TestProgressFileDoneContract/FailContract | ✅ |
| test_emit_noop_when_disabled | cli:TestProgressFileEnvFallbackAndNoOpEvents* | ✅ |
| （env 回退/recon.py:191） | cli:TestProgressFileEnvFallbackAndNoEventsOnHelp | ✅ 等价改写 |
| （-h 不发事件） | cli:TestProgressFileEnvFallbackAndNoEventsOnHelp | ✅ |

### 不平移文件

| 文件 | 项数 | 理由 |
|---|---|---|
| test_jsintel.py | 15 | jsintel 模块 c3 拍板为暂不移植（Go 版无该子命令，README/--help 文案一致）；如后续拍板移植再平移 |
| test_portscan.py | 8 | 同上（portscan） |
| test_fix1_parity.py | 3 | Python 侧对 Go 行为的反向锚定（make_outdir 清洗/保留名/crt.sh 控制字符）——Go 即参照实现，无平移对象 |

## 3 项 Python 环境失败 —— 非平移缺口

`test_verify_and_evidence.TestVerifySubs` 的 test_dns_lookup / test_verify_subs_marks_alive /
test_run_verify_writes_outputs 三项：断言依赖"`.invalid` 假域名必须解析失败（NXDOMAIN）"，
本机 Clash fake-ip 将其解析为 198.18.0.128/2001:2::75 → 本机必红，GitHub runner 上应绿。
Go 侧对应测试**改写锚点为 127.0.0.1 字面量**（TEST-PORT 与 PARITY 反复强调的纪律），
因此这三项红不代表 Go 缺测试——是环境性失败，已按等价改写收口。

## 改写说明汇总

1. NXDOMAIN 断言 → 127.0.0.1 字面量锚点（fake-ip 环境纪律）；
2. sha1 → digest（sha256 前 16 hex，fix1 两引擎同步迁移）；
3. reverse 域名正则 lookaround → label 校验函数（RE2 限制，黄金用例钉死）；
4. 指纹 28 条正则逐条 RE2 兼容确认（无 lookaround/反向引用），全规则预编译 + 自然语言回归（本轮补）；
5. 时间相关断言（idempotent/zip 文件名）→ clock 注入 + 行数/集合口径；
6. 私网判定：Go 标准库自实现 Python 3.8 全集 + 动态 python 探针单测（netutil:TestIPBlockedMatchesPython）。
