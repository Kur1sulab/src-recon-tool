# DESIGN-native.md —— 信息收集工具（Gio 原生壳）视觉规范落地对照

> 本文是 desktop-native（Gio 自绘壳）视觉规范落地对照文档。
> **现行规范 = 「浅色工程台 Light Bench」（见第七节，2026-10-05 用户裁定改浅色）**；深色「石板声呐」仅存 git 历史（tag/commit 可回溯），**禁止照本文第一~六节的深色令牌表把浅色改回深色**——深色令牌表仅作两主题对照存档。不做双主题机制、设置页没有「界面主题」行。
> 规范令牌来源：`desktop-go/docs/design-proposals/C-tokens.css` 的 `[data-theme="light"]` 覆盖块（31 令牌）。
> 本文记录浅色令牌到 `desktop-native/internal/ui/theme.go` 的 Go 常量映射，以及六页的视觉要点。

## 一、令牌对照表（css → Go 常量，逐值一致）

> ⚠️ 本节为**深色「石板声呐」时代的旧对照存档**：常量名沿用至今，但 theme.go 里的值已是第七节浅色工程台（同名换值）。改浅色常量请以第七节与 C-tokens.css `[data-theme="light"]` 块为准。

### 石板五级底（冷蓝相，纵深全靠阶差）

| css 令牌 | 值 | Go 常量（theme.go） | 消费点 |
|---|---|---|---|
| `--s0` | `#0c1116` | `ColS0` | 主区画布（app.go mainArea 卡底） |
| `--s1` | `#101820` | `ColS1` | 侧栏/顶栏底、输入井底、tab 未启用钮底 |
| `--s2` | `#151f28` | `ColS2` | 面板卡标准底（statCards/概要卡/工具卡/设置卡）、tab 默认底 |
| `--s3` | `#1b2732` | `ColS3` | 行悬停井、次按钮底（探测/自检/导出钮） |
| `--s4` | `#223040` | `ColS4` | 任务行选中井（文字用 Tx1，不落 Tx3） |

### 精密边框三阶（全部 1dp 发丝线）

| css 令牌 | 值 | Go 常量 | 消费点 |
|---|---|---|---|
| `--ln-1` | `#1e2b36` | `ColLn1` | 表头下发丝线（hairline）、顶栏底线 |
| `--ln-2` | `#273745` | `ColLn2` | （预留：面板描边，本轮未消费） |
| `--ln-3` | `#354857` | `ColLn3` | （预留：悬停边/idle 族成文例外边线，本轮未消费） |

### 文字三阶（冷蓝灰）

| css 令牌 | 值 | Go 常量 | 消费点 |
|---|---|---|---|
| `--tx-1` | `#dee6ec` | `ColTx1` | 正文/数据值/输入框文字 |
| `--tx-2` | `#9aabb9` | `ColTx2` | 表头/标签/提示/次文（对 s2 7.1:1） |
| `--tx-3` | `#7a90a4` | `ColTx3` | 脚注/快捷提示（只上 s0–s3，禁上 s4） |

### 品牌青鹤（唯一强调色，绝不参与状态语义）

| css 令牌 | 值 | Go 常量 | 消费点 |
|---|---|---|---|
| `--acc` | `#3cb8a8` | `ColAcc` | 主按钮底（ContrastBg）、导航选中轨 |
| `--acc-hi` | `#74d6c7` | `ColAccHi` | 运行态文字、选中 tab/导航文字 |
| `--acc-lo` | `#1d4a43` | `ColAccLo` | （预留：描边档，本轮未消费） |
| `--acc-ink` | `#04201b` | `ColAccInk` | 主按钮文字（ContrastFg） |
| `--acc-bg` | `#102e2b` | `ColAccBg` | 导航/tab 选中井底 |

### 状态色族（绿=完成 橙=警示 红=故障 灰=待命）

| css 令牌 | 值 | Go 常量 | 消费点 |
|---|---|---|---|
| `--ok` | `#63bd80` | `ColOk` | 已完成状态文字、导出成功回执、依赖正常点 |
| `--ok-lo` | `#2a5c3c` | `ColOkLo` | （未消费） |
| `--ok-bg` | `#15271d` | `ColOkBg` | 成功横条底（新建任务 okBanner） |
| `--warn` | `#d9a353` | `ColWarn` | 依赖有问题文字、mock 不可达点 |
| `--warn-lo` | `#6b5426` | `ColWarnLo` | （未消费） |
| `--warn-bg` | `#2a2216` | `ColWarnBg` | （预留：警示横条底） |
| `--err` | `#e07b6c` | `ColErr` | 失败状态文字、错误横条文字、停止按钮文字 |
| `--err-lo` | `#6e3a33` | `ColErrLo` | （未消费——曾误用作停止钮底色，本轮已改 err-bg，见「硬边界」） |
| `--err-bg` | `#2c1d1a` | `ColErrBg` | 错误横条底、停止按钮底 |
| `--idle` | `#5b6f82` | `ColIdle` | （未消费；若作 LED 须离 s3 井底 ≥3:1） |
| `--idle-bg` | `#131c24` | `ColIdleBg` | （预留） |
| `--zebra` | `#121b23` | `ColZebra` | 长表斑马纹（比面板底沉半档） |

### 字体与字号阶梯

| css 令牌 | 值 | Go 常量/做法 | 消费点 |
|---|---|---|---|
| `--font-ui` | Segoe UI / Microsoft YaHei UI / … | `loadFaces()`：中文主字体逐级回退 `msyh.ttc` → `msyhl.ttc` → `simsun.ttc`（Windows 全系自带），三级全缺写一行 stderr 提示并回退 Gio 内置 gofont；Consolas 附加注册作等宽 | 全局 th.Shaper |
| `--font-mono` | Cascadia Mono / Consolas / … | `MonoTF="Consolas"`（`monoLabel()` 仅给 ASCII 数据列挂等宽字体名；缺字体静默回退默认） | 表格数据列/回执行/路径行 |
| `--fs-11` | 11px | `Fs11 = unit.Sp(11)` | 表头/tab/铭牌/脚注 |
| `--fs-12` | 12px | `Fs12 = unit.Sp(12)` | 徽标/回执/表格数据 |
| `--fs-13` | 13px | `Fs13 = unit.Sp(13)`（th.TextSize 基准） | 正文/导航项 |
| `--fs-14` | 14px | `Fs14 = unit.Sp(14)` | 输入框 |
| `--fs-15` | 15px | `Fs15 = unit.Sp(15)` | 页题/品牌名（Weight=SemiBold） |

### 间距 / 圆角 / 布局

| css 令牌 | 值 | Go 常量 | 消费点 |
|---|---|---|---|
| `--sp-1..6` | 4/8/12/16/20/24px | `Sp1..Sp6 = unit.Dp(同值)` | 全部留白 |
| `--r-1/2/3` | 3/5/8px | `R1/R2/R3 = unit.Dp(同值)` | 小徽标/输入井与次按钮/面板大卡 |
| `--r-full` | 999px | tab 胶囊直接 `unit.Dp(999)` | 模块 tab 胶囊 |
| `--w-side` | 224px | `SideW = unit.Dp(224)` | 侧栏宽 |
| `--h-topbar` | 52px | `TopH = unit.Dp(52)` | 顶栏高 |
| `--pad-x` | 24px | `PadX = unit.Dp(24)` | 主区水平留白 |
| 表格密度 | 30px 行高 | `RowH = unit.Dp(30)` | 全部表格行（与生产 data 表同级紧凑） |

### 本轮不收的令牌（与融合裁定一致）

- `--info` 三档、`--sev-*` 别名、`--w-drawer`、`--idle-lo`：桌面壳本轮均无真实消费页，全部**不进** theme.go（连候选常量都没建）。哪页真用到了，先在这里登记再补常量。
- 不新增任何 tokens.css 里没有的颜色；theme.go 常量与 tokens.css 逐值一一对应，多一个都要先过规范流程。

## 二、硬边界（WCAG 红线，本轮复核过消费点）

1. **Tx3 禁上 S4**（4.06:1）：S4 只用于任务行选中井，其上文字是 Tx1（选中标记「▶ 选中」）与 Tx2——已核对 page_results.go taskListTable。
2. **Idle 不作文字色**（对 s2 仅 3.21:1）：`statusColor()` 对 created/stopped 一律回退 Tx2，没有用 Idle 作文字。
3. **Idle LED 禁上 S3 井底**（2.92:1）：工具页依赖状态点用 Ok/Warn 实心点 + Tx3「检测中」，本轮没有用 Idle 点。
4. **-lo 描边档只描边、禁作文字**：曾发现停止按钮误用 `ColErrLo` 作底色（骨架轮），本轮已改 `ColErrBg` 底 + `ColErr` 字（对齐生产 `.btn-danger{color:var(--err);border-color:var(--err-lo)}` 的取色语义）；grep 复核 -lo 族在 theme.go 之外零消费。

## 三、六页视觉要点

1. **仪表盘**：页题 15sp；四张统计卡（s2 底 r3，72dp 高，数字 15sp 等宽、按状态着色，横纵间距统一 Sp3）；最近 8 条任务表（表头 11sp Tx2 + 发丝线 + 斑马纹，数据串 12sp 等宽）；空态提示 Tx2 次文档档（空页时它是唯一可读内容兼行动指引）。
2. **新建任务**：单卡表单（s2 r3，内衬 3/3/4/4）；标签 12sp Tx2；输入井 s1 r2 高 42dp、文字 14sp Tx1、hint Tx3；模块九宫单选（三列，基线轮起为 10 模块四行）；可选参数提示随模块联动（11sp Tx3 等宽）；主按钮「开始扫描」青底墨字；错误横条 err-bg/err、成功横条 ok-bg/ok（最多 5 行——指引类必达文案防裁尾，Gio 截断无省略号）。
3. **结果**：标题行右侧「停止选中任务」（err-bg/err，仅运行中显示，恒占 96dp 槽位——出现/消失不挤动右侧「导出证据包」）与「导出证据包」（s3 底，打包中变 s1/Tx3「正在打包…」并真禁用）；导出回执行 12sp 等宽（成败色来自结构化回执位，成绿/败红）；停止失败回执走标题行下 err 横条槽（停止钮与 Esc 共用，任务终态即清）；模块 tab 胶囊行（80dp 定宽 × 26dp 高，横向 List 可滚——11 枚胶囊 880dp ≤ 主区 908dp 全见，选中 acc-bg/acc-hi + Medium 字重）；任务列表 50 行/页分页（‹ 上一页 / 第 x/y 页 / 下一页 ›，边界钮 s1/Tx3 灰显且 Disabled 真禁用）＋列表视口钳 min(300dp, 可用高)——满一页时分页条与任务详情不再被挤出窗口；概要卡 + 过程记录表 50 行/页，表头「时间/模块/事件/详情」权重 0.7/0.9/1/3；基线任务在过程行尾追加「每检查结论」行（8 行：模块=检查中文名，事件=结论/未运行，详情=[level] 结论文本）。
4. **工具**：十模块清单（名称 Tx1 / 说明 Tx2 / 子命令键 11sp Tx3 等宽，行间 Sp1）；外部依赖状态卡（7dp 实心圆点：绿=正常 橙=有问题 灰=检测中，路径行 11sp Tx3 等宽）；数据落点卡（两列布局：定宽 96dp 标签 + 12sp 等宽路径——含中文标签靠补空格对不齐）；分区间距统一 Sp4。
5. **设置**：整页持久 List 滚动（四卡+标题超一屏时「关于」可达）；Python 卡（输入井 + 「自检」次钮（后台跑，自检中按钮禁用） + 「保存并生效」主钮 + 结论行按成败分档着色 + 当前生效路径 11sp Tx3 等宽）；Go 引擎卡（同构：recon-go.exe 输入井 + 「自检」跑 `recon-go -h` + 「保存并生效」+ 探测路径绿字 + 构建命令 11sp Tx3 等宽「进入仓库 engine-go 目录执行 go build -o recon-go.exe .」——引擎缺失显式给指引不静默；后台自检未回时显「检测中…」不误报「未找到」）；输出目录卡（只读展示产物/证据包路径，12sp 等宽 Tx1）；关于卡（三条大白话：是什么/纯本地无 AI/子进程跑本地流水线）。**没有「界面主题」行。**
6. **暴露面（第六页，基线轮 2026-10-06 新增）**：页题「暴露面」+ 副题「域名暴露面基线体检 · 8 项检查一键跑 · 零凭据」；输入卡（目标域名输入井 + 青底主钮「一键跑全部检查」，运行中灰显 s1/Tx3「检查进行中…」；Go 引擎缺失时 warn 横条给构建指引；错误 err 横条 / 成功 ok 横条带任务 id）；「检查项（8）」分区卡列表（横向 List 可滚），每卡：顶部 6dp 结论色条（level→ColOkBg/ColWarnBg/ColErrBg/ColAccBg 族）+ 8dp 相位 LED + 中文名 + 相位字（未运行/排队中/检查中…/已跳过/执行失败/有结论）+ 检查键 11sp 等宽 + 右缘「原始 JSON ▸/▾」折叠钮；有结论时展示 `[level] 结论文本`（族色字）+ 生成时间 + 风险明细（`· [level] 标题 — 详情`，族色）+ 引擎摘要行（11sp 等宽 Tx2）+ 折叠的原始 JSON（s0 凹井 11sp 等宽，超 2000 字节截断并注明产物路径）。产物契约 = engine-go baseline/result.go 冻结包络；缺文件=「未运行」不编造，error 非空=失败态红字。

## 四、键盘流

| 按键 | 行为 | 实现 |
|---|---|---|
| Tab / Shift+Tab | 焦点遍历（Gio 输入树内建：Clickable 注册 `key.FocusFilter`，见 gioui.org v0.10.3 widget/button.go:151） | 无需应用层代码 |
| Esc | 停止选中的运行中任务（无选中/已终态则无动作） | app.go updateKeys：`key.Filter{Name: key.NameEscape}` |
| Ctrl+1..6 | 切换 仪表盘/新建任务/结果/工具/设置/暴露面（键位按 `len(pageNames)` 派生，不再写死） | app.go updateKeys + pageKeyNames/applyPageKey（纯函数，baseline_page_test 钉住） |

## 五、三态覆盖清单

- **空**：仪表盘无任务/结果页无任务/该模块筛选为空/过程记录为空——各有一句大白话空态卡（emptyHint，s2 r3 居中 Tx2 次文档——空页唯一可读内容兼行动指引，不用弱注档）；暴露面页无目标时引导语空态卡、目标无产物时 8 张「未运行」空卡（不编造）。
- **载**：环境自检未回（工具页「检测中…」、设置页「尚未自检」、设置页 Go 引擎卡「检测中…」）；设置页/工具页自检与 mock 探测后台跑（「自检中…」「探测中…」反馈，UI 事件循环不再同步起子进程冻结窗口）；证据包导出进行中（按钮变「正在打包…」并真禁用拒重复点击，回执经 channel 回事件循环）；数据轮询 400ms 节流；暴露面页运行中（主钮灰显「检查进行中…」且 Disabled 真禁用，卡片相位逐检查点亮：排队中/检查中…，后台节拍对任务库快照签名变化即 Invalidate 唤帧）。
- **错**：新建任务校验错误（errBanner，目标格式不合法）；证据包导出失败（红字回执，成败色来自结构化回执位）；停止失败（结果页标题行下 err 横条槽，停止钮与 Esc 共用，任务终态即清）；暴露面页目标格式错误（err 横条 + 输入井下方即时格式提示）/ Go 引擎缺失（warn 横条 + 构建命令，不静默）/ 任务整体失败或被 Esc 停止（输入卡终态横条：失败红/停止橙，去结果页看过程记录）/ 检查级失败（卡红字 fail 态，fail 事件不中断其余检查）；settings.json 损坏兜底零值；任务库损坏兜底空库（store 层既有行为）；产物 JSON 损坏（「产物解析失败」失败态，不冒充引擎结论）。

## 六、暴露面仪表盘执行器（2026-10-06，基线轮）

- recon-go.exe baseline 第二子进程：`<recon-go.exe> --progress-file <dataDir>/progress/<id>.jsonl baseline -d <域名>`（--progress-file 在子命令之前；与 python recon.py 九模块并行共存，按子命令选引擎分支）。
- 解析顺序：settings.go_engine_path > RECON_GO_EXE 环境变量 > repoRoot/engine-go/recon-go.exe 探测；缺失显式报错 + 构建指引（设置页可改，自检跑 `recon-go -h`）。
- 进度事件与 python 引擎同构：外层 start/done(module=baseline) + 内层每检查 start/done|fail|skipped；聚合流程走完即 done（个别检查 fail 不改终态）；Tailer/monitor 零改动复用。
- 产物：outDirFor 三方同名目录的 `{secheaders,webfiles,mailsec,archives,sslchain,dnsrec,whois,geoasn}.json`，包络 = engine-go baseline/result.go 冻结 schema（两线对测试不对实现：引擎 schema 单测 + 桌面 baselineview fixture 单测）。

## 七、浅色主题换装（2026-10-05，用户裁定改浅色）

- 色板整块切换为「**浅色工程台 Light Bench**」——逐值转译自 `desktop-go/docs/design-proposals/C-tokens.css` 的 `[data-theme="light"]` 覆盖块（31 令牌，34 组 WCAG 硬门槛配对实测全过，依据 C-dual-theme.md §9）。
- 层级方向与深色相反：面板最亮（纸面白 #ffffff），骨架/画布/井位反向压灰（画布 #eef1f4、骨架 #e5eaef、交互井 #e4eaef、强井 #d7dfe6）。
- 文字三阶换冷蓝墨（主文 #1c2833 对面板 14.99:1；次文 #46596a；弱注 #52687a 不上强井）。
- 强调色取**深青档**：主按钮底 #0d7668 + 白字（5.51:1），悬停由变亮反转为加深 #0a6357（7.15:1）；焦点环同深青。
- 状态色族换浅色文字档（绿 #17722f / 橙 #8f5e00 / 红 #c0362e，各带描边与淡底伴生档）；待命灰两主题同值 #5b6f82（LED 对白面板 5.20:1）。
- 落点：`internal/ui/theme.go` 色板常量整块替换（单点换装，组件层零改动）；同名变量名不变，深色「石板声呐」保留在 git 历史（tag/commit 可回溯）。
