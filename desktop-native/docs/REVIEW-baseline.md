# REVIEW-baseline.md —— 基线轮（域名暴露面 8 检查）独立冷复核

> 复核员未参与本轮施工（冷复核）。复核对象 = `src-recon-tool` 仓库 HEAD `e7573e4`
> （工作区无对已跟踪文件的未提交改动，`git status --short` 实证），本轮四个提交：
> `e0e31d5`（engine-go baseline 8 检查）→ `dacb6da`（desktop 第六页+执行器接线）→
> `1f1fbf4`（engine-go 审计+对抗终修）→ `e7573e4`（desktop 对抗 F6 修复）。
> 对照设计 = `pentest/webcheck-research-20261005/RESEARCH-webcheck-20261005.md` §⑤
> （§5.0–5.9，即 engine 提交信息所称「report §5.0-5.9」；desktop 侧另有
> `desktop-native/docs/DESIGN-native.md` §六）。复核全程只读生产代码 + 自跑构建/测试/
> 真窗验证；零生产代码改动。

**结论：验收通过。** §5.0–5.9 八模块逐条落地有码有测；零新增三方依赖实证成立；
UI 六页齐、每检查有 UI、浅色一致、界面零授权字样；两线 build+test 复核员亲跑全绿；
真窗口六页走查 + taskkill 完成。3 处低危偏差见 §五（不影响验收）。

---

## 一、报告 §5 的 8 模块逐条落地核对

每模块抽查 2-3 个实现要点（读码定位）+ 验收标准对应用例（测试文件定位）。
基线包共 **83 个测试函数**（含对抗轮 `adv_baseline_test.go` 21 个），`go test -count=1`
基线包 14.29s 全绿（亲跑，见 §四）。

### §5.1 sec_headers（安全响应头）

实现要点（`engine-go/internal/baseline/secheaders.go`）：

1. 8 条规则表驱动（`secRules`，secheaders.go:59-68），HSTS 阈值 10886400 常量
   （secheaders.go:41，报告冷读订正值 hsts.js MIN_MAX_AGE）；
2. 手动逐跳循环上限 5 跳（`secMaxHops`，secheaders.go:37）+ 落点过 HopPolicy
   （secheaders.go:289,337-341，`hopPolicyFor` 可注入）；
3. Cookie 审计（`judgeCookies`，secheaders.go:187-208：Secure/HttpOnly/SameSite
   任一缺失记 issue）+ WAF 特征表（`wafSignatures`，secheaders.go:219-235，含 3 条
   国产占位并标注待校准）。

验收用例：`TestSecRulesTable/BadValues/Absent`（8 规则正反样例，secheaders_test.go:28-83）、
`TestHSTSBoundary`（**10886399 判 warn 且提示 10886400**，secheaders_test.go:85-99——
报告验收 2 的边界值逐字落地）、`TestSecHeadersMockweb`（:136）、
`TestSecHeadersPrivateRedirectBlocked`（:233，私网落点被拒）。

### §5.2 webfiles（网站文件）

实现要点（`webfiles.go`）：

1. robots.txt 逐行解析 Disallow/Allow/Sitemap（`parseRobots`，webfiles.go:42-71，
   空 Disallow 不进字典），非空 Disallow 回喂 `paths_extra.txt`（webfiles.go:278-282）；
   `paths --extra` 合并去重在 `internal/paths/paths.go:38-64`（`mergeExtra`+`RunPaths` 变参）；
2. sitemap `encoding/xml` 逐 token 解析，遇 DOCTYPE/ENTITY 立即拒
   （`parseSitemap`，webfiles.go:90-94「不可信 XML 双保险」）；
3. 终修轮 F1/F2 加固在位：robots Sitemap 行封顶 10（webfiles.go:25）、**首跳过闸**
   （webfiles.go:247-250，恶意 robots 驱动的外联源先过 hop 策略，被拒记 notes+risks
   零请求）、40s 抓取软预算（webfiles.go:255-258）、单源 loc 封顶 500（webfiles.go:271-274）。

验收用例：`TestParseSitemap`（webfiles_test.go:31-49，**DOCTYPE/ENTITY 恶意样例被拒**
= 报告验收 2）、`TestWebfilesMockweb`（:123）、`TestClassifyHrefs`（:102，同站/子域候选/
外链归类）；`internal/paths/extra_test.go:14-30`（mergeExtra 剔重剔空 + **extra 条目真实
进探测循环** = 报告验收 3）；对抗 `TestAdvRobotsSitemapFirstHopGated`（adv:162）、
`TestAdvWebfilesSitemapBounded`（adv:820，15 行 robots 只抓 ≤10 源）。

### §5.3 mailsec（邮件安全）

实现要点（`mailsec.go`）：

1. MX 服务商指纹表 12 条（mailsec.go:22-35）+ SPF all 四态判定（`spfAllVerdict`，
   mailsec.go:81-94：-all ok / ~all warn / ?all info / **+all fail 高危**）；
2. include/redirect 递归展开上限 2 层（`spfExpandMaxDepth`，mailsec.go:97；
   `walkSPF` 带 visited 防环+总量封顶）；
3. DMARC p=/pct= 分档（`dmarcVerdict`，mailsec.go:175-195：无记录或 p=none 判可伪造
   fail，pct<100 归 warn「部分生效」）；DKIM 恰 8 个 selector（mailsec.go:50）+
   公钥位数解析（`dkimKeyBits`，mailsec.go:201-238：PEM 包裹→ParsePKIXPublicKey→
   RSA/ECDSA/ed25519 取位数）。

验收用例：`TestMailsecSPFAllVerdicts`（mailsec_test.go:37，+all/−all/~all/?all 全态）、
`TestWalkSPFDepth`（:95-113，**第 3 层不展开**=报告 2 层上限）、`TestDKIMKeyBits`
（:115-128，**2048/1024 两位数样例**=报告验收 2）、`TestMailsecDNSAllFail`
（:170，DNS 全挂→fail 事件不阻塞聚合=报告验收 4）；对抗 `TestAdvMailsecHostileTXT`（adv:478）。

### §5.4 archives（历史归档）

实现要点（`archives.go`）：

1. CDX 分页拉取（showNumPages→逐页，`fetchCDX` archives.go:148-200）+ 行数上限
   50000（`cdxMaxLines`，:37，超限置 truncated）+ 3 次退避重试（:131-144）；
2. URL 规范化去重（`normalizeCDXURL`，:73-89：scheme/host 小写、去 fragment；
   终修 F4：非 http/https 返回 ""——javascript: 行不进产物）；
3. 敏感分流（扩展名 11 种 + 关键词 7 个，:92-95）→ `archives_high.txt` 单列
   （:257-265）+ 与 paths 字典交叉 dup/new（`crossPathsDict`，:123-128，只出清单不探测）。

验收用例：`TestCDXDedupAndClassify`（archives_test.go:56-113，**/backup.zip→dup、
/db.sql→new** = 报告验收 4）、`TestCDXPaginationAndTruncate`（:116，**超限截断带
truncated 标记**=报告验收 3）、`TestArchivesFailNoFabricate`（:159，接口失败不编造=
报告验收 2）；对抗 `TestAdvArchivesHostileCDX`（adv:749，敌意行只收合法行）。

### §5.5 ssl_chain（TLS 证书链）

实现要点（`sslchain.go`）：

1. `tls.DialWithDialer` 10s（:193）握手期免校验取链（`netutil.ProbeTLSConfig` 单点，
   :115），取证后显式 `x509.Verify` 建链（:135-140，`sslRoots` 可注入本地测试根池）；
2. 自签判定链仅 1 张且 RawIssuer==RawSubject（:133）；失败归类四态
   （`classifyVerify`，:71-89：过期/域名不匹配/信任链不完整（自签）/其他）；
3. 协议矩阵 4 档 Min/Max 钳位各拨一次、串行+间隔（`sslVersions` :32-40，
   `sslGap` :27，默认仅 443、`Options.Ports` 扩展）。

验收用例：`TestSSLExpired/NameMismatch/SelfSigned/ValidChain`（sslchain_test.go:132-230，
**本地 CreateCertificate + 本地 tls.Server 三类判定全离线**=报告验收 1）、
`TestSSLProtocolMatrix`（:231-256，**服务钳 MinVersion=1.2 时 1.0/1.1 判未启用**=报告
验收 2）、`TestSSLNonTLS`（:257，非 TLS 端口记「非 TLS 服务」不按失败=报告验收 4）。

### §5.6 dnsrec（DNS 记录，含 DoH 决策点）

实现要点（`dnsrec.go`）：

1. 标准库 8 类 A/AAAA/CNAME/MX/NS/TXT/SRV/PTR（jobs 表 :167-201），worker 8
   （`runDNSJobs`，:107-134）、单查询 3s（`dnsTimeout`，baseline.go:337）；
2. **DoH 决策按报告方案 a 执行**：`DoHBase = "https://dns.google/resolve"` 免 key
   （dnsrec.go:24），`Options.DoH` 默认关（baseline.go:110），**不引 miekg/dns**；
   关闭时 SOA/CAA/DS/DNSKEY 明示「未查（--doh 未开）」不编造（dnsrec.go:326-331）；
   终修 F5：DoH Status 在场但非 float64 按查询失败（dnsrec.go:57-65，堵敌意源
   字符串 Status 逃过 DNSSEC 判定）；
3. verify 合并：`Options.KnownA` 在场复用不重复查询（dnsrec.go:168-175）；失败分类
   分字段（`dnsErrClassify`，:137-159：NXDOMAIN/超时）。

验收用例：`TestDNSRecEightTypes`（dnsrec_test.go:84，mock resolver 注入）、
`TestDNSRecDoHOff`（:126-137，**四类逐键断言「未查」**=报告验收 2）、
`TestDNSRecDoHOn`（:139，httptest stub DoH）、`TestDNSRecErrClassification`（:182）、
`TestDNSRecKnownADedup`（:208）；对抗 `TestAdvDoHHostileJSON`（adv:556，敌意 DoH
不再误报 DNSSEC）。

### §5.7 whois（WHOIS 注册信息）

实现要点（`whois.go`）：

1. RDAP 优先（`RDAPBase` rdap.org 免 key，whois.go:252），events 按 eventAction 归集、
   registrar 取 vcard fn、nameservers ldhName（`parseRDAP`，:91-159），字段缺失置空；
2. 43 端口回退：IANA→注册局→注册商两级（`whoisMaxHops=2`，:238；referral 链
   :270-288），正则覆盖 .com/.net Verisign 与 .cn CNNIC（:171-174），未结构化输出
   原文 40 行截断+标注（:296-306）；终修 F3 形状闸 `referralHostOK`（:218-235，
   仅域名字符集/≤253/必含点——恶意注册局文本不能驱使拨任意 host:43）；
3. tranco 排名 `--rank`（Options.Rank）默认关、失败静默（:309-316）。

验收用例：`TestParseRDAP`（whois_test.go:31）、`TestParseWhoisText`（:72，43 文本
fixture 正则=报告验收 2）、`TestWhoisFallback43`（:129，**RDAP 不可达自动落 43**=
报告验收 4）、`TestWhoisTranco`（:179）、`TestWhoisTimeoutSilent`（:214，超时 fail
静默=报告验收 5）；对抗 `TestAdvWhoisReferralLoop`（adv:658）+
`TestAdvWhoisReferralShapeGate`（adv:876，十形态）。

### §5.8 geoasn（IP 归属 / ASN）

实现要点（`geoasn.go`）：

1. 三源串行回退 ipwho.is → ip-api.com → geojs（`GeoSources`，geoasn.go:30-34，与报告
   实读 location.js 序一致），按源字段映射（`parseGeoInfo`，:84-119）；
2. 假 200 防御（`geoFake200`，:71-81：status=error / success=false 判失败）+ 限速
   1 QPS（`geoRateInterv1`，:39；n 次外联 n-1 次 sleep）；
3. 多源分歧：首源成功拉次源交叉一次，国家不一致并列输出+`conflict` 标记
   （:194-211,220-227）。

验收用例：`TestGeoParsers`（geoasn_test.go:27，三家异构 fixture=报告验收 1）、
`TestGeoFallback`（:63，**首源失败自动降级**=报告验收 2）、`TestGeoFake200Defense`
（:88）、`TestGeoConflict`（:107）、`TestGeoRateLimit`（:143-159，**真实计时 2 IP
≥1s**=报告验收 4）+ `TestGeoSleepCallCount`（:161，sleep 次数=外联数-1 机制复核）。

### §5.0 共同底座 + §5.9 聚合与桌面接入

- **包络冻结**：`result.go:37-46` `{check,target,url,generated_at,conclusion,risks,data,error}`
  四级 level 常量（:14-19），Risks/Data 空时序列化为 []（`NewResult`，:53-62）；
  两线对测试不对实现（result_test.go + desktop baselineview_test.go 双侧钉住）。
- **聚合器**：串行执行（baseline.go:140-184），每检查 60s（:148-149）/总预算 5min
  （:151-152），超预算发 skipped 不落盘（:166-169），检查级 fail 不上抛不改终态
  （:177-181）；产物 json+txt+evidence/baseline/ 副本（`writeProducts`，:206-226）。
- **CLI**：`baseline` 子命令（cli.go:345-396）——`-d` 必填+域名形状闸 exit 2（:362-365）、
  `--checks` 归一化前置（未知名 exit 2 零网络副作用，:367-373）、`-u` 缺省 PickBase
  （:384-386）、`AllowPrivate: true` 桌面契约（:389）。`knownCmds` 含 baseline
  （cli.go:55）。
- **验收用例**：`TestNormalizeChecks`（baseline_test.go:112，空=8 项/别名 sec_headers、
  ssl_chain/未知报错/去重）、`TestRunEventsProductsOffline`（:141，事件序+json/txt/
  evidence 三产物）、`TestRunSkipsWhenBudgetExhausted`（:190，**skipped 不落盘**）、
  `TestRunPerCheckTimeout`（:222，超时 fail 事件+error 包络）、
  `TestRunCheckFailureDoesNotBreakOthers`（:258，**fail 不中断**）、
  `TestAdvAggregatorHostileEndToEnd`（adv:898）。
- **report/paths 集成**：report.go Collect 8 槽位（:95-104，缺文件零值不编造）+
  report.md 基线章（`baselineSectionKeys` :418-428 + `baselineLevelZH` :430）；paths
  `--extra`（见 §5.2）；mockweb 独立 sec 场景（`internal/mockweb/sec_test.go` 在场）；
  `netutil.ProbeTransport/ProbeTLSConfig` 免校验策略单点化（netutil/fetch.go:101,114）。
- **桌面接入**：执行器按子命令选分支——`desktop-native/internal/engine/runner.go:281-286`
  baseline → recon-go.exe 第二子进程（`--progress-file` 在子命令前，:286）；
  `ResolveGoEngine` 三级回退（:117-122，settings > RECON_GO_EXE > 仓库探测）；cmdSet
  第十成员 baseline（:30）。会话层域名形态闸 `TestCreateTaskBaselineDomainShape`
  （baseline_session_test.go:14）。进度事件内层 module=检查名与桌面
  `baselineEventStates`（baselineview.go:215-237）对齐。

## 二、零新增三方依赖（含 DoH 决策）

| 核对项 | 命令/证据 | 结果 |
|---|---|---|
| engine-go go.mod | `cat go.mod` | 仅 `gopkg.in/yaml.v3`（c2 提交 af5bf7d 引入的既有唯一依赖，非本轮） |
| 基线包 import | `grep -rh '^\t"' internal/baseline/*.go` 排除标准库 | **空输出**——8 模块全标准库 |
| 本轮 4 提交 | `git diff --stat <c>^ <c> -- engine-go/go.mod engine-go/go.sum desktop-native/go.mod desktop-native/go.sum`（c ∈ e0e31d5, dacb6da, 1f1fbf4, e7573e4） | **4 个提交均零改动**（`git show --name-only` 复核 go.mod/go.sum 触碰数=0） |
| DoH 决策 | dnsrec.go:3-6,24 + baseline.go:110 | 报告 §5.6 **方案 a**（dns.google/resolve 免 key + `--doh` 默认关）落地，未引 miekg/dns，与报告建议一致 |

desktop-native go.mod 仅 gioui.org + golang.org/x/sys（既有）。

## 三、UI 核对（六页 / 每检查有 UI / 浅色 / 零授权字样）

- **六页齐**：`app.go:37` `pageNames = {仪表盘, 新建任务, 结果, 工具, 设置, 暴露面}`；
  六个 page_*.go 文件在场；`TestSixPageRouting`（baseline_page_test.go:14）钉路由；
  真窗 Ctrl+1..6 走查六页全部渲染（§六截图）。
- **每检查有 UI**：①暴露面页 8 张分区卡（`baselineChecks` 8 槽位，baselineview.go:39-48，
  顺序=引擎 checksOrder；页上实测「检查项（8）」）；②结果页过程表 8 子检查中文映射
  `baselineEventLabels`（results.go:35-45）+ 基线任务表尾「每检查结论」行
  （`BaselineConclusionRows`，baselineview.go:150-167 + page_results.go:267-269）+
  模块表「基线检查」行（results.go:28）与 tab 胶囊；③新建任务模块九宫含「基线检查」
  （p2 截图实测）；④工具页模块清单含「基线检查 域名暴露面基线体检（8 项检查一键跑）」
  （p4 截图实测）；⑤设置页 Go 引擎卡（p5 截图实测：路径+自检+保存+**构建命令指引
  不静默**）。映射一致性有 `TestModuleLabelsBaseline`（baselineview_test.go:155）钉住。
- **浅色一致**：theme.go 单一色板「浅色工程台 Light Bench」（theme.go:21 起，纸面白
  0xffffff 面板/冷灰画布/深青强调）；暴露面页全部取色走同一常量集
  （`baselineLevelColor` baselineview.go:195-207：ok→ColOkBg/warn→ColWarnBg/fail→
  ColErrBg/info→ColAccBg；`baselinePhaseColor` :299-309；page_baseline.go 无任何新色值，
  `grep "0x" page_baseline.go` 零命中）。六页真窗截图目视同一色板，无混色。
- **零授权字样**：`grep '"[^"]*授权[^"]*"'` 与 `'"[^"]*白名单[^"]*"'` 对 internal/ui 全部
  非测试 .go —— **字符串字面量零命中**（11 处命中全为代码注释/标识符，如
  session.go:330 注释自述「产品铁律：界面零授权/白名单字样」）；六页截图目视复核
  无授权/白名单文案（顶栏自述「专精信息收集 · 纯本地运行 · 无 AI · 不联网上报」）。

## 四、两线 go build + go test（复核员亲跑，2026-10-06）

engine 线（`cd engine-go`）：

```
$ go version
go version go1.24.1 windows/amd64
$ go build ./... && go build -o recon-go-review-cold.exe .
（无输出，退出码 0；exe 10,913,280B，验后已删）
$ go test -count=1 ./...
ok  internal/apiunauth      0.826s
ok  internal/asset          0.389s
ok  internal/baseline      14.290s
ok  internal/cli            5.564s
ok  internal/fingerprint    1.022s
ok  internal/icp            0.991s
ok  internal/mockweb        3.708s
ok  internal/netutil        3.902s
ok  internal/parity        90.226s
ok  internal/paths          2.275s
ok  internal/poc            1.158s
ok  internal/redteam_adv2   7.117s
ok  internal/report         1.985s
ok  internal/reverseip      1.582s
ok  internal/subdomain      2.653s
ok  internal/toolrun        2.669s
（16 包 ok，退出码 0）
```

desktop 线（`cd desktop-native`）：

```
$ go build ./... && go build -o recon-native-cold.exe .
（无输出，退出码 0；exe 18,188,800B，验后已删）
$ go test -count=1 ./...
?   recon-native              [no test files]
ok  recon-native/internal/engine      30.413s
ok  recon-native/internal/store       14.789s
ok  recon-native/internal/ui          16.709s
ok  recon-native/internal/whitelist    0.336s
（4 包 ok，退出码 0）
```

## 五、偏差与低危观察（不影响验收，登记在案）

1. **（低）`--doh`/`--rank`/`--ports`/`-i` 未做成 CLI 旗标**：`Options.DoH/Rank/Ports/IPs`
   在包级齐备且默认关（外联最小化纪律满足），但 cli.go baseline 分支只暴露
   `-d/-u/--checks`（cli.go:347-351）——报告 §5.6 的「--doh 开关」与 §5.7 的「--rank
   开启」目前只在包 API 可达，终端用户无法打开。桌面壳亦只传 `-d`（DESIGN-native.md
   §六口径一致）。属功能面收窄，非纪律违规。
2. **（低）tranco www 前缀两次尝试未实现**：报告 §5.7 引 rank.js:12-14 的 www 两次
   尝试逻辑；whois.go:311 单次请求、失败静默跳过（`grep -n "www" whois.go` 零命中）。
   附加字段，影响极小。
3. **（低）§5.8 输入腿缺 verify 产物接线**：报告「输入 verify 产物 subdomains_live.json
   的 IP 集 + 用户 -i 直传」——现实现 = `Options.IPs` 直传（包级）或对目标域 A 解析
   cap 5（geoasn.go:141-155）；CLI 未接 subdomains_live.json 读取，也未暴露 -i。默认
   腿可用，报告全量输入面未接满。
4. **（记录）§5.1「跟随+不跟随双请求」实现为单通道手动逐跳**：链/终响应头/Cookie 一次
   取得，请求量更小；secheaders.go:7-10 注释自述该取舍，验收以逐跳可见+HopPolicy
   拒绝为准，报告验收条目全部有对应用例——属已声明的实现细节替代，不算偏差。

## 六、真窗口终验（复核员亲跑）

脚本：`desktop-native/docs/review-native-shots/cold-review-baseline.ps1`（PrintWindow
抓帧 + Ctrl+1..6 切页；零目标接触——只切页看 UI，不输入目标不点扫描）。

```
WINDOW hwnd=0x2709F2 pid=68636
SHOT cold-p1-dashboard.png … SHOT cold-p6-baseline.png（六张全出）
KILLED pid=68636   ← Stop-Process 验证已退出
```

六张截图同目录 `cold-p1..p6*.png`。目视结论：

- p1 仪表盘：四统计卡（任务总数 5/运行中 0/已完成 3/失败 0）+ 最近任务表；
- p2 新建任务：目标输入 + 模块单选组（含**基线检查**）+ 可选参数提示；
- p3 结果：任务表（多条**基线检查**模块行）+ 模块 tab + 分页 + 导出按钮；
- p4 工具：模块清单含「**基线检查 域名暴露面基线体检（8 项检查一键跑）**」+ mock 探测
  + 外部依赖状态点；
- p5 设置：Python 卡 + **Go 引擎卡**（路径「C:\Users\18270\src-recon-tool\engine-go\recon-go.exe」
  + 自检/保存并生效 + 绿字「已探测到」+ 构建命令指引行）+ 输出目录卡；
- p6 暴露面：页题+副题「域名暴露面基线体检 · 8 项检查一键跑 · 零凭据」+ 目标输入 +
  青底「一键跑全部检查」+「检查项（8）」空态引导卡。

六页同为浅色工程台色板，无授权/白名单字样。截图中左上角 GPU/CPU/RAM 悬浮数字为本机
硬件监控 OSD 叠印（环境因素，非应用渲染物）。第一次跑脚本因 P/Invoke 漏声明
keybd_event 未切页即截（六张同页），修正声明后重跑得出上述有效结果；两次进程均已 kill。

## 七、未跑/未验事项（如实声明）

- `go vet`、gofmt 检查未跑（ask 要求为 go build + go test，两者均已亲跑）。
- 引擎对真实公网目标的联网集成用例（报告各节「短测跳过」档）未跑——本轮复核同样
  零真实目标接触，与施工轮测试目标红线一致。
- 暴露面页「输入目标→一键跑→逐检查点亮」的活体链路未在真窗重演（p6 仅空态+输入卡；
  运行态/结论态以单测 TestBaselineEventStates/TestBaselineCheckPhase 与施工轮
  f4/p6 系列截图为证）。复核员判定：活体跑会向外部域名发起真实检查外联，冷复核
  保持零目标接触更稳妥。
