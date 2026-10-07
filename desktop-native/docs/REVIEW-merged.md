# REVIEW-merged.md —— 集成轮（engine-go 公开化 + desktop-native 直调重写）独立冷复核

> 复核员未参与本轮施工（冷复核）。复核对象 = 仓库 `src-recon-tool` HEAD `88a9d1c`
> **+ 暂存区（staged）201 项改动**——本轮施工成果（engine-go internal→顶层公开包、
> desktop 子进程壳退役改进程内直调）尚未提交，`git status --short` 实证 staged 201 项、
> 未 staged 仅 `docs/GOAL-20261002-go-desktop.md`（基线轮总结，文档）。两线 build+test
> 均在该 staged 树上亲跑。复核全程只读生产代码 + 自跑构建/测试；**零生产代码改动、
> 未运行 GUI**（ask 禁令）。

**结论：5 项核对 4 项通过、1 项有条件通过**（单 exe 自包含——默认形态成立，但
os/exec 外部工具子进程通道在合并二进制内存活，见 §一）；发现 4 处低危观察 + 1 处
台账表述需补注，无 high/medium，不阻塞验收。真窗目验项移交《人工目验清单.md》
集成轮专项节。

---

## 一、单 exe 自包含（有条件通过）

### 1.1 go version -m：零 Python 依赖 ✅

复核员亲跑 `go build` 重建两 exe 后 `go version -m`（验后两 exe 已删）：

```
$ go version -m engine-go/recon-go-review-merged.exe
	engine-go/recon-go-review-merged.exe: go1.24.1
	path	github.com/Kur1sulab/src-recon-tool/engine-go
	dep	gopkg.in/yaml.v3	v3.0.1	h1:fxVm/…7CA=
	build	CGO_ENABLED=0
	build	GOOS=windows  GOARCH=amd64

$ go version -m desktop-native/recon-native-review-merged.exe
	desktop-native/recon-native-review-merged.exe: go1.24.1
	path	recon-native
	dep	gioui.org	v0.10.3
	dep	github.com/Kur1sulab/src-recon-tool/engine-go	v0.0.0-…  => ../engine-go (devel)
	dep	golang.org/x/{sys v0.39.0, net v0.48.0, image, text, exp/shiny}
	dep	gopkg.in/yaml.v3	v3.0.1  // indirect（经 engine）
	build	CGO_ENABLED=0
```

- engine exe 唯一三方依赖 `gopkg.in/yaml.v3`（既有）；native exe = gioui + engine-go
  （`replace ../engine-go` 本地 devel）+ x/* 传递族。**两 exe 零 Python、零解释器嵌入、
  CGO_ENABLED=0**。exe 体积：engine 10,924,544 B / native 19,039,232 B。

### 1.2 源码 grep os/exec：desktop 零残留；engine-go 扫描子进程通道存活 ⚠️

```
$ grep -rn "os/exec" desktop-native --include="*.go" | grep -v _test.go
（零命中，exit=1）                                    ← 桌面侧子进程壳退役实证

$ grep -rn "os/exec" engine-go --include="*.go" | grep -v _test.go
engine-go/internal/parity/parity.go:14    ← 测试基建（import "testing"，仅被 _test 引用）
engine-go/toolrun/oneforall.go:15         ← 外部工具子进程适配层
engine-go/toolrun/scanutil.go:9
```

- **parity 不进二进制**：`go list -deps .`（desktop）实证链接面里 import os/exec 的
  只有 `engine-go/toolrun`；parity/mockweb 均不在依赖图。
- **toolrun 被链接**（经 `subdomain/subdomain.go:18` import），两条子进程通道：
  1. **OneForAll（Python）**：`subdomain.go:206` 扫描时读 `os.Getenv("ONEFORALL_HOME")`
     → `toolrun/oneforall.go:126-131` 读 `RECON_PYTHON`（缺省 `python`）→
     `exec python <home>/oneforall.py --target <domain>`。**门槛**：ONEFORALL_HOME
     已设且目录含 oneforall.py；未设时 `oneforall.go:42-44` 返回空 +
     `subdomain.go:216` 打印「未设置 ONEFORALL_HOME，降级使用证书日志查询」。
  2. **subfinder（Go 二进制）**：`scanutil.go:28-37` 先找 `<cwd>/tools/bin/subfinder.exe`
     再 PATH；缺席返回 ""，`RunSubfinderContext` 对空 path 返回 nil（subdomain.go:53-55）。
- **判定**：环境干净（无 ONEFORALL_HOME、无 subfinder）时合并单 exe **零子进程、
  纯进程内 HTTP，自包含成立**；但「grep 无 os/exec 起扫描子进程残留」**字面不成立**
  ——toolrun 是 toolrun 包头声明的铁律设计（「外部工具一律保持子进程调用、不重写」，
  oneforall.go:1-8），属声明式可选通道而非意外残留，且降级链完备。**风险点在
  ONEFORALL_HOME + RECON_PYTHON 的机器残留环境**：设过的机器上桌面扫描会真起
  Python 子进程。已列入人工目验清单（环境检查项）。
- **台账补注要求**：`desktop-native/docs/SECURITY-ADVISORIES.md` ADV-20261004-01
  「消解」条目称「污点源与汇双端不存在」——对 desktop 壳侧代码成立（app.go 的
  Getenv/NewSession pythonPath/ResolvePython 确已删除，grep 实证），但同款源汇形态
  （`RECON_PYTHON` → `os/exec` 起 python）在 `engine-go/toolrun/oneforall.go:126`
  随引擎链接进合并二进制。语义仍属「使用者显式配置外部工具」by-design 家族
  （门槛 = ONEFORALL_HOME，且参数列表调用无 shell、路径清洗三道），不构成回退，
  但该条台账的消解声明在合并二进制语境下应补一句边界说明。

### 1.3 仓库目录依赖 / 临时目录自足 ◐

- **任务库/设置/证据包自足 ✅**：`session.go:286-294` dataDir =
  `%LOCALAPPDATA%\recon-native`（退 UserConfigDir / `.recon-native`）；tasks.json、
  settings.json、evidence/*.zip 全在 dataDir 下（store.go:35、settings.go:23、
  evidence.go:114）。
- **扫描产物 out/ 有仓库/cwd 倾向 ◐**：`session.go:262-283 findRepoRoot()` 从 exe
  目录与 cwd 各上溯 4 级找 `engine-go/` 目录判仓库根，找不到回退 `"."`——产物落
  `repoRoot/out/<目标清洗名>`（runner.go:274-280）。脱离仓库的单 exe 产物落到
  **启动时 cwd 相对路径**（session.go:261 注释自述此取舍），设置页/工具页只读卡
  如实展示该落点（page_settings.go:42-43、page_tools.go:122,127），不误导；但
  「临时目录自足」的运行时行为（exe 拷到任意目录双击）**未实测**——GUI 禁令下
  只能静态证据，移交人工目验清单第 1 项。
- **cwd 约定路径两处**：`toolrun.FindSubfinder` 找 `<cwd>/tools/bin/subfinder.exe`、
  `recordVersion` best-effort 写 `<cwd>/tools/bin/VERSIONS.md`（scanutil.go:29,166）——
  仅在 subfinder 通道激活时触达。
- 引擎侧全部落盘经 `netutil.SafeWrite` 收口到产物目录参数（grep 全量 17 处写点
  逐一核对，无仓库源树写入）。

## 二、公开 API 面最小（基本达标，2 观察）

- **包级清点**（`go doc` 逐包导出 decl 计数，2026-10-07 实跑）：

  | 公开包 | 导出 decl | desktop 直调 import | 链接进 exe |
  |---|---|---|---|
  | apiunauth/asset/fingerprint/icp/jsonx/paths/poc/report/reverseip/toolrun | 2–9 各 | 10 包直调（apiunauth,asset,baseline,cli,fingerprint,icp,paths,report,reverseip,subdomain） | 14 包（+jsonx/netutil/poc/toolrun 传递） |
  | baseline | 15（Run/RunContext/Options/Result/Conclusion/Risk/NormalizeChecks/ErrUnknownCheck/常量+注入点） | | |
  | netutil | 18（Fetch/FetchOpt.Ctx/SafeWrite/SafeOutdir/CheckHTTPURL/HopPolicy/ProbeTLSConfig…） | | |
  | mockweb | 13 | ×（仅测试 import） | × |
  | internal/parity、internal/redteam_adv2 | 留 internal ✅ | | × |

- **internal 收口实证**：`git status` 的 R 记录显示 15 个包 internal→顶层平移，
  parity/redteam_adv2（纯测试/对抗基建）留在 `internal/`——公开面没有把测试基建
  一并放出。
- **观察 A（mockweb 公开的理由未成文）**：mockweb 全仓零非测试引用，但 desktop
  三个集成测试跨模块消费（`inproc_integration_test.go:15`、`adv_inproc_integration_test.go:15`、
  `session_e2e_test.go`）——engine-go 若 internal 化它，desktop 测试将无法 import。
  公开判定合理，但 engine-go/README「进程内嵌入契约」节未写明这一条，建议补一句。
- **观察 B（Run/RunContext 双变体并存）**：README 只承诺 `Run*Context` 为嵌入面，
  旧 `Run(...)` 全部委托保留（如 baseline.go:148-150）。公开面约翻倍，属兼容取舍，
  建议未来 CHANGELOG 标注 deprecated。
- 包级词表只读约定（README 新增契约 2）实证成立：`Endpoints/Rules/PathsList/
  CheckLabels/GeoSources` 全仓 grep 仅 map 读取，零写入点（`[]`/`=` 赋值形态零命中）。

## 三、并发安全抽查（通过）

- **ctx 贯穿 ✅**：`runner.go:174` 每任务 `WithCancel(Background)` → 八模块全走
  `RunContext/...Context`（runner.go:341,355,364,373,386,396,414 + allrunner.go 各步）
  → `netutil/fetch.go:239-242` 取消咽喉（`req.WithContext(opt.Ctx)`）→
  `toolrun` 经 `CommandContext`（scanutil.go:69-71、oneforall.go:122-131）。
  baseline 双档取消：未起步检查循环头拦截发 skipped 不落盘（baseline.go:185-189）、
  在跑检查 `runOne` select ctx.Done 落「已取消」包络（:235-239）。
  验收面：**12 个包各带 ctxcancel_test.go 共 16 个测试函数**（本轮新增，grep 实数），
  baseline 的预取消用例断言「秒级收敛 + 零产物」。
- **sink 锁 ✅**：`Runner.mu` 单锁护 jobs/stopping/sink/modules 四件（SetSink:99-103、
  SetModuleFunc:106-113、runModule 读表:251-253、emit→sinkOrDefault:115-123）——
  运行中调用导出接缝不再是并发 map 读写（审计 low#4 修复在位）。`Store.mu` 全方法
  持锁（store.go:130-253 逐方法核对），Get/List 返回值副本，AppendProgress 进度
  只追加不改写已快照区间 + 去抖 flushProgress 持锁重排（:216-228）。UI 侧
  envInfo 自带锁（app.go:40-47），后台导出/mock 探测经缓冲 1 channel 回事件循环
  （app.go:96,106,358-379）。
- **panic 兜底 ✅（残留已文档化）**：桌面 job goroutine 单点 recover（runner.go:250-260，
  审计 high#1）；引擎 per-check goroutine `safeCheck` recover（baseline.go:249-258）。
  残留：检查内部 worker goroutine（dnsrec 池）不在两级兜底面——README「进程内嵌入
  契约」§1 明示该边界，属如实声明的已知残留，非隐瞒。
- **Start/Stop 竞态 ✅**：Stop 对无作业任务也插 stopping 旗（runner.go:288-291）、
  Start 注册前自检放弃（:165-172）；终态裁决在 cancel() 之前采样 ctx.Err()
  （:184-186，注释写明次序原因）。
- **对抗覆盖 ✅**：`adv_inproc_integration_test.go` 10 用例（stop 锤击记账、stop 后
  goroutine 真退出、在飞 paths 取消、baseline 超时抢占、敌意目标零副作用、
  makeOutDir 越界钳制、模块闸零网络、进度洪水封顶、多任务真模块互扰）。

## 四、铁律（通过）

| 项 | 证据 | 结论 |
|---|---|---|
| 浅色 | theme.go 色板 = 「浅色工程台 Light Bench」（纸面白面板 0xffffff、画布 0xeef1f4、深青强调 0x0d7668、文字三阶 0x1c2833/0x46596a/0x52687a，逐值对 DESIGN-native.md §七）；page_baseline.go grep `0x` **零命中**，全部取色走 theme 常量（baselineview.go:195-207 baselineLevelColor→ColOkBg/ColWarnBg/ColErrBg/ColAccBg 族） | ✅ |
| 零 AI | desktop 非测试 grep（chat/llm/gpt/openai/anthropic/对话/智能/助手…）唯一实质命中 = 关于页自decl文案（page_settings.go:170「零 AI 功能…」）；engine 公开面 CLI `knownCmds` 无 llm 槽位（cli.go:50-62 注释自述「公开面不保留 AI 词汇」）；设置页关于卡改口「无需安装 Python 或外部引擎」（page_settings.go:70）。**观察**：report.go:118-121 + :402-406 保留 `llm_summary.md` 条件渲染路径（默认无此文件→「## 8. LLM 辅助小结」章节不渲染，零 AI 字样不进产物；但死代码与自家声明不一致，见 §六-2） | ✅（带 1 观察） |
| 目标默认授权 | whitelist.Check = 纯格式卫生（whitelist.go 全文无名单成员判定；控制字符/协议/端口 0/穿越/非 ASCII 拒绝），runner.go:145-147、session.go:80 注释口径一致「目标本身全部默认授权（用户裁定 2026-10-05）」 | ✅ |
| 零授权字样 | 非测试代码双引号字符串 `"[^"]*授权[^"]*"` 与 `"[^"]*白名单[^"]*"` **双双零命中**（exit=1）；宽口径（含注释）命中 11 处全为代码注释/标识符。**观察**：whitelist.go:23 注释残留「归一后仍是名单内主机」措辞——包已无名单，注释未随 2a59e07 换装更新 | ✅（带 1 化妆项） |

## 五、两线 go build + go test（复核员亲跑，2026-10-07）

engine 线（`cd engine-go`）：

```
$ go version
go version go1.24.1 windows/amd64
$ go build ./... && go build -o recon-go-review-merged.exe .
（无输出，退出码 0；exe 10,924,544 B，验后已删）
$ go test -count=1 ./...
?   	github.com/Kur1sulab/src-recon-tool/engine-go	[no test files]
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/apiunauth	1.060s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/asset	0.666s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/baseline	11.614s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/cli	5.551s
?   	github.com/Kur1sulab/src-recon-tool/engine-go/cmd/recon-go	[no test files]
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/fingerprint	1.008s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/icp	1.092s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/internal/parity	46.759s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/internal/redteam_adv2	6.874s
?   	github.com/Kur1sulab/src-recon-tool/engine-go/jsonx	[no test files]
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/mockweb	2.223s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/netutil	1.945s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/paths	1.213s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/poc	1.026s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/report	1.113s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/reverseip	1.038s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/subdomain	1.482s
ok  	github.com/Kur1sulab/src-recon-tool/engine-go/toolrun	2.166s
（16 包 ok，退出码 0）
```

desktop 线（`cd desktop-native`）：

```
$ go build ./... && go build -o recon-native-review-merged.exe .
（无输出，退出码 0；exe 19,039,232 B，验后已删）
$ go test -count=1 ./...
?   	recon-native	[no test files]
ok  	recon-native/internal/engine	8.700s
ok  	recon-native/internal/store	0.391s
ok  	recon-native/internal/ui	1.310s
ok  	recon-native/internal/whitelist	0.232s
（4 包 ok，退出码 0）
```

## 六、偏差与低危观察（不阻塞验收，登记在案）

1. **（低·口径）toolrun 外部工具子进程通道随引擎链接进合并单 exe**（§1.2）：
   声明式设计（toolrun 包头铁律）+ 默认休眠（双通道全优雅降级），但与「grep 无
   os/exec 起扫描子进程残留」的字面验收口径冲突。处置建议（供编排方裁定，本轮
   未动代码）：① README/台账补边界说明（最小）；② 桌面直调面显式关闭 ONEFORALL_HOME
   通道（如在 subdomain 包装层清空该 env 读取，需动生产代码另立轮次）。
2. **（低）report.go LLM 死路径**：`Collect` 读 `llm_summary.md`（report.go:118-121）+
   RenderMD 条件渲染「## 8. LLM 辅助小结」（:402-406）。合并产品无任何代码生成该
   文件 → 章节永不出现，零 AI 字样铁律不破；但与 cli.go:50「公开面不保留 AI 词汇」
   的自decl不一致，建议后续轮次随公开面清理一并摘除（含 rune 4000 截断逻辑）。
3. **（低）findRepoRoot `"."` 回退的产物落点漂移**：脱离仓库的单 exe 产物落启动
   cwd 相对路径（session.go:282），从不同目录启动产物散落。设置页/工具页如实
   展示当前落点，不算隐瞒；「临时目录自足」的运行时行为待人工目验（清单第 1 项）。
4. **（化妆）whitelist.go:23 注释残留「名单内主机」措辞**（§四）。
5. **（记录）ADV-20261004-01「消解」表述需补注**（§1.2 末段）——台账文件属文档，
   本轮零改动遵禁令，留给施工/编排方处理。

## 七、未跑/未验事项（如实声明）

- **GUI 未运行**（ask 禁令）：六页真窗回归、直调活体链路（建任务→模块直调→事件
  流→产物→导出）、单 exe 便携性（拷出仓库运行）、Esc 停止收敛——全部移交
  《人工目验清单.md》「集成轮专项」。运行态以单测为证：inproc/adv_inproc 集成
  13 用例（mockweb 本地假站全链路）+ session_e2e 全绿。
- `go vet`、`gofmt`、`go test -race` 未跑：ask 要求为 build+test（均已亲跑）；-race
  沿既有台账口径（本机无 cgo/gcc）。
- ONEFORALL_HOME / subfinder 激活路径未实测（避免在本机布置 Python 工具链），
  休眠路径（env 未设）有源码+降级打印佐证。
- 引擎对真实公网目标的联网用例未跑——零真实目标接触，与两线测试目标红线一致
  （全部 127.0.0.1 httptest/mockweb/包内注入桩）。
- `go version -m` 的 vcs.revision=88a9d1c + vcs.modified=true 与 staged 树一致，
  二进制即本轮施工成果；staged 改动**尚未提交**，验收通过后请编排方按 pathspec
  纪律收口提交。
