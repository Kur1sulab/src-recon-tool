# DESIGN-native.md —— 信息收集工具（Gio 原生壳）视觉规范落地对照

> 本文是 desktop-native（Gio 自绘壳）与生产视觉规范「深色控制室·石板声呐」的对照文档。
> 规范唯一来源：`desktop-go/frontend/css/tokens.css`（逐值不动）+ `desktop-go/frontend/DESIGN.md` front matter。
> 本文只做一件事：把 css 令牌映射到 `desktop-native/internal/ui/theme.go` 的 Go 常量，并记录五页的视觉要点。
> 深色「石板声呐」是唯一规范主题；不落地浅色、不做双主题机制、设置页没有「界面主题」行（融合裁定，缓议至视觉轮 r2 后另立项）。

## 一、令牌对照表（css → Go 常量，逐值一致）

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
| `--font-ui` | Segoe UI / Microsoft YaHei UI / … | `loadFaces()`：优先注册 `C:\Windows\Fonts\msyh.ttc`（雅黑 TTC，尖峰已验 faces=2），Consolas 附加注册作等宽；都缺失回退 Gio 内置 gofont | 全局 th.Shaper |
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

## 三、五页视觉要点

1. **仪表盘**：页题 15sp；四张统计卡（s2 底 r3，72dp 高，数字 15sp 等宽、按状态着色）；最近 8 条任务表（表头 11sp Tx2 + 发丝线 + 斑马纹）；白名单卡内目标串用 12sp 等宽 Tx2。
2. **新建任务**：单卡表单（s2 r3）；标签 12sp Tx2；输入井 s1 r2 高 40dp、文字 14sp Tx1、hint Tx3；模块九宫单选（三列）；可选参数提示随模块联动（11sp Tx3 等宽）；主按钮「开始扫描」青底墨字；错误横条 err-bg/err、成功横条 ok-bg/ok（最多 3 行）。
3. **结果**：标题行右侧「停止选中任务」（err-bg/err，仅运行中显示）与「导出证据包」（s3 底，打包中变 s1/Tx3「正在打包…」）；导出回执行 12sp 等宽（成绿/败红）；模块 tab 胶囊行（26dp 高，选中 acc-bg/acc-hi + Medium 字重）；任务列表 50 行/页分页（‹ 上一页 / 第 x/y 页 / 下一页 ›，边界钮 s1/Tx3 灰显）；概要卡 + 过程记录表 50 行/页，表头「时间/模块/事件/详情」权重 0.7/0.9/1/3。
4. **工具**：九模块清单（名称 Tx1 / 说明 Tx2 / 子命令键 11sp Tx3 等宽）；外部依赖状态卡（7dp 实心圆点：绿=正常 橙=有问题 灰=检测中，路径行 11sp Tx3 等宽）；数据落点卡（产物目录/证据包目录 12sp 等宽）。
5. **设置**：Python 卡（输入井 + 「自检」次钮 + 「保存并生效」主钮 + 结论行着色 + 当前生效路径 11sp Tx3 等宽）；输出目录卡（只读展示产物/证据包路径，12sp 等宽 Tx1）；白名单卡（只读清单，13sp 等宽 Tx1，明示「不可在此修改」）；关于卡（三条大白话：是什么/纯本地无 AI/白名单红线）。**没有「界面主题」行。**

## 四、键盘流

| 按键 | 行为 | 实现 |
|---|---|---|
| Tab / Shift+Tab | 焦点遍历（Gio 输入树内建：Clickable 注册 `key.FocusFilter`，见 gioui.org v0.10.3 widget/button.go:151） | 无需应用层代码 |
| Esc | 停止选中的运行中任务（无选中/已终态则无动作） | app.go updateKeys：`key.Filter{Name: key.NameEscape}` |
| Ctrl+1..5 | 切换 仪表盘/新建任务/结果/工具/设置 | app.go updateKeys：`key.Filter{Required: key.ModCtrl, Name: key.Name("1".."5")}` |

## 五、三态覆盖清单

- **空**：仪表盘无任务/结果页无任务/该模块筛选为空/过程记录为空——各有一句大白话空态卡（emptyHint，s2 r3 居中 Tx3）。
- **载**：环境自检未回（工具页「检测中…」、设置页「尚未自检」）；证据包导出进行中（按钮变「正在打包…」并拒重复点击，回执经 channel 回事件循环）；数据轮询 400ms 节流。
- **错**：新建任务校验错误（errBanner，目标格式不合法）；证据包导出失败（红字回执）；停止失败（转结果页红字提示）；settings.json 损坏兜底零值；任务库损坏兜底空库（store 层既有行为）。

## 六、浅色主题换装（2026-10-05，用户裁定改浅色）

- 色板整块切换为「**浅色工程台 Light Bench**」——逐值转译自 `desktop-go/docs/design-proposals/C-tokens.css` 的 `[data-theme="light"]` 覆盖块（31 令牌，34 组 WCAG 硬门槛配对实测全过，依据 C-dual-theme.md §9）。
- 层级方向与深色相反：面板最亮（纸面白 #ffffff），骨架/画布/井位反向压灰（画布 #eef1f4、骨架 #e5eaef、交互井 #e4eaef、强井 #d7dfe6）。
- 文字三阶换冷蓝墨（主文 #1c2833 对面板 14.99:1；次文 #46596a；弱注 #52687a 不上强井）。
- 强调色取**深青档**：主按钮底 #0d7668 + 白字（5.51:1），悬停由变亮反转为加深 #0a6357（7.15:1）；焦点环同深青。
- 状态色族换浅色文字档（绿 #17722f / 橙 #8f5e00 / 红 #c0362e，各带描边与淡底伴生档）；待命灰两主题同值 #5b6f82（LED 对白面板 5.20:1）。
- 落点：`internal/ui/theme.go` 色板常量整块替换（单点换装，组件层零改动）；同名变量名不变，深色「石板声呐」保留在 git 历史（tag/commit 可回溯）。
