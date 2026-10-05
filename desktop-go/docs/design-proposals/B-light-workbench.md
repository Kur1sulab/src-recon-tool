---
version: alpha
name: Light Bench
description: 信息收集工具（src-recon-tool 桌面端）的浅色工程台视觉体系——工程白五级底、品牌墨青唯一强调、圆形 LED、等宽数据列、斑马纹数据行；与深色方案 A 共享全部变量名契约，落地为纯 tokens.css 换值。
colors:
  primary: "#0e7668"
  secondary: "#46586a"
  tertiary: "#1a7f37"
  neutral: "#ffffff"
  canvas: "#e3e9f0"
  chrome: "#eef2f6"
  well: "#f0f4f8"
  well-strong: "#e2e9f0"
  zebra: "#f7fafb"
  line-hair: "#d8e0e8"
  line-card: "#c6d2dd"
  line-hover: "#a9bac9"
  text-primary: "#16232f"
  text-secondary: "#46586a"
  text-muted: "#536879"
  accent-hi: "#0b8272"
  accent-lo: "#a7cdc6"
  accent-ink: "#ffffff"
  accent-bg: "#e2f2ef"
  status-ok: "#1a7f37"
  status-ok-lo: "#92c6a1"
  status-ok-bg: "#ecf7ef"
  status-warn: "#8f5c00"
  status-warn-lo: "#d3ac64"
  status-warn-bg: "#faf2de"
  status-bad: "#c22c33"
  status-bad-lo: "#e2a4a9"
  status-bad-bg: "#fbeef0"
  status-idle: "#566b7e"
  status-idle-lo: "#c2ccd6"
  status-idle-bg: "#edf1f5"
  status-info: "#0b5fce"
  status-info-lo: "#a5c4ec"
  status-info-bg: "#e9f1fb"
typography:
  body:
    fontFamily: "system-ui, 'Segoe UI', 'Microsoft YaHei UI', 'PingFang SC', 'Noto Sans CJK SC', sans-serif"
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.55
  title:
    fontFamily: "system-ui, 'Segoe UI', 'Microsoft YaHei UI', 'PingFang SC', 'Noto Sans CJK SC', sans-serif"
    fontSize: 15px
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "0.3px"
  label:
    fontFamily: "system-ui, 'Segoe UI', 'Microsoft YaHei UI', 'PingFang SC', 'Noto Sans CJK SC', sans-serif"
    fontSize: 11px
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "0.06em"
  data:
    fontFamily: "ui-monospace, 'Cascadia Mono', Consolas, 'Courier New', monospace"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.6
    fontFeature: "tnum"
rounded:
  sm: 3px
  md: 5px
  lg: 8px
  full: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 20px
  xxl: 24px
components:
  panel:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
  nav-item:
    backgroundColor: "{colors.chrome}"
    textColor: "{colors.text-secondary}"
    rounded: "{rounded.md}"
    padding: 9px 10px
  nav-item-hover:
    backgroundColor: "{colors.well}"
    textColor: "{colors.text-primary}"
  nav-item-active:
    backgroundColor: "{colors.accent-bg}"
    textColor: "{colors.text-primary}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.md}"
    padding: 6px 14px
  button-primary-hover:
    backgroundColor: "{colors.accent-hi}"
    textColor: "{colors.accent-ink}"
  button-secondary:
    backgroundColor: "{colors.well}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
    padding: 6px 14px
  button-secondary-hover:
    backgroundColor: "{colors.well-strong}"
    textColor: "{colors.text-primary}"
  button-stop:
    backgroundColor: "{colors.well}"
    textColor: "{colors.status-bad}"
    rounded: "{rounded.md}"
    padding: 6px 14px
  button-stop-hover:
    backgroundColor: "{colors.status-bad-bg}"
    textColor: "{colors.status-bad}"
  input:
    backgroundColor: "{colors.chrome}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
  table-header:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.text-secondary}"
  table-row-zebra:
    backgroundColor: "{colors.zebra}"
    textColor: "{colors.text-primary}"
  status-badge-created:
    backgroundColor: "{colors.status-idle-bg}"
    textColor: "{colors.text-secondary}"
    rounded: "{rounded.full}"
  status-badge-running:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.accent-hi}"
    rounded: "{rounded.full}"
  status-badge-done:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.status-ok}"
    rounded: "{rounded.full}"
  status-badge-fail:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.status-bad}"
    rounded: "{rounded.full}"
  status-badge-stopped:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.status-warn}"
    rounded: "{rounded.full}"
  led:
    backgroundColor: "{colors.status-idle}"
    size: 8px
  log-well:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text-secondary}"
    rounded: "{rounded.md}"
  panel-foot:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.text-muted}"
  banner-offline:
    backgroundColor: "{colors.status-warn-bg}"
    textColor: "{colors.status-warn}"
  toast:
    backgroundColor: "{colors.well}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
  toast-ok:
    backgroundColor: "{colors.status-ok-bg}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
  toast-error:
    backgroundColor: "{colors.status-bad-bg}"
    textColor: "{colors.status-bad}"
    rounded: "{rounded.md}"
---

## Overview

「浅色工程台 · Light Bench」是「信息收集工具」桌面端（src-recon-tool，Wails/WebView2，五页：任务列表 / 新建任务 / 任务详情 / 证据包 / 设置）的**浅色**视觉体系提案，与深色方案 A（现行「石板声呐」，见 `frontend/DESIGN.md`）竞稿。

**方案 B 的一句话定位：把界面做成工程师白天用的数据图纸台——白纸面板、冷灰画布、墨青刻度，一切为了长时间读表、比对、复制证据，而不是夜间值守。**

**为什么是浅色工程台（对方案 A 四条论点的正面回应）：**

1. **内容主体是结构化数据，不是遥测流。** 五页里四页（任务列表 / 任务详情 / 证据包 / 设置）的主视图是表格与表单，任务详情里结构化工具表 + 阶段进度轨才是"结论层"，原始日志尾只是"真相源备查"。读表、逐行比对、框选复制到报告，是白纸黑字的阅读模式；A 方案"值守扫读"的论证只覆盖了运行中的那几分钟。
2. **等宽数据语汇在浅色图纸上同样成立。** 安全工具的数据密排浅色传统很长（Burp 的 HTTP history 表、Nessus 的发现表都是浅底等宽列——本轮调研已核对 portswigger.net 与 docs.tenable.com 原文）；等宽字体 + `tabular-nums` 的列位稳定靠的是字体纪律，不靠底色深浅。A 方案"终端语汇在浅色会割裂"的论点把"终端拟物"误当成了可读性前提。
3. **证据出口是报告，不是屏幕。** 本产品的终点动作是"查看报告 / 导出证据包"；白底截图贴进交付文档不需要反色处理，色值在打印与对方屏幕上的还原也更稳定。深色界面截图进白底报告会产生大片黑块。
4. **与用户的漏扫作业台同族同貌。** 同为桌面安全作业面板，B 与深色版共享同一套家族基因（多级底色 + 单一品牌强调 + 状态色只做语义 + 等宽数据纪律），但把"夜班仪表"换成"日班图纸"；两案不是优劣关系，是**场景假设不同**（见「与方案 A 的关系与选型」）。

**B 对 A 的继承（不是推倒重来）：** 变量名契约、五页信息架构、密度、字号、圆角、间距、动效纪律、图标规范、键盘协议全部照搬 A——B 只在**色板、纵深模型、阴影、纹理透明度**四个点分叉。因此 A/B 之选是可逆的、低成本的（落地为整文件替换 `tokens.css`，`app.css` / `index.html` / `js/**` 零改动，实证见「落地步骤」）。

**动效纪律（硬约束，与 A 逐字相同）：** `animation`/`transition` 只允许 `opacity` 与 `transform` 两个通道；颜色、边框、填充类状态一律即时切换、不做补间；持续动画全站仅 LED 呼吸一种；全部动效在 `prefers-reduced-motion: reduce` 下压至 0.01ms。

**产品与文案合规：** 窗口标题 / 侧栏铭牌 / 页面名一律「信息收集工具」「新建任务」（已落地并经 grep 验证，本轮不改动）；界面零 AI 功能、零对话组件、零联网调用、零遥测——本提案不引入任何新组件类型，仅改变既有组件的配色。

## Colors

全部颜色只存在于 `css/tokens.css`（唯一颜色来源，本目录附整文件草稿 `B-tokens.css`），组件层 `css/app.css` 禁止裸色值。

- **工程白五级底（`--s0`→`--s4`）**：画布 `#e3e9f0` → 骨架 `#eef2f6` → 面板 `#ffffff` → 交互井 `#f0f4f8` → 强井 `#e2e9f0`。冷蓝相（hue≈212，与 A 同族，保证两案切换时品牌认知连续）。
  - **浅色纵深模型与深色相反，但变量语义不变**：深色版"越内越亮"，浅色版"越内越亮到白、凹井下沉回灰"——`--s2` 面板是最亮一档（白卡浮在灰画布上），`--s3/--s4` 是面板上**下陷**的井，`--s0` 同时充当画布地板与最深凹井（日志底）。`app.css` 对这些变量的消费关系（日志井用 `--s0`、输入井用 `--s1`、行悬停用 `--s3`、次按钮悬停用 `--s4`）在两案下都成立。
- **精密边框三阶（`--ln-1/2/3`）**：`#d8e0e8` / `#c6d2dd` / `#a9bac9`，全部 1px；对面板对比度 1.33 / 1.54 / 1.99，落在既定发丝带（1.3–2.5）内。浅色下发丝线比深色版更依赖这 1px 的实色，禁止用阴影替代行分隔线。
- **文字三阶（`--tx-1/2/3`）**：`#16232f` / `#46586a` / `#536879`。**弱注档 `--tx-3` 对全部五级底（含强井 s4）实测 4.73–5.79:1 全过 AA**——这是 B 相对 A 的一处实际改善：A 的 `--tx-3` 对强井仅 4.06:1 不过（A 因此立了"弱注不上强井"硬禁）；B 不需要这条禁令，但仍保留"弱注只用于脚注/快捷键"的用途约束。表头仍用 `--tx-2`（7.33:1），不用弱注档。
- **品牌墨青（`--acc` 族）**：`#0e7668`，与 A 的青鹤同色相 172°，浅底下转深。是全站唯一强调色，只用于——焦点环、激活轨、刻度记号、主按钮底、运行态。**绝不参与状态语义。** 与 A 的关键差异：深色版青底上配暗墨字（`--acc-ink` 深色），浅色版青底反白（`--acc-ink: #ffffff`，对青底 5.51:1）；`--acc-hi` 从"亮青字"变为"亮一档的悬停底 / running 徽章字"（对白底 4.72:1 过 AA）。
- **状态色族（`ok` / `warn` / `err` / `idle` + 新增可选 `info`）**：完成绿 `#1a7f37`（深色版同值沿用）、警示琥珀 `#8f5c00`、故障红 `#c22c33`、待命灰蓝 `#566b7e`。严重度映射沿用安全工具惯例（本轮调研核对 Trivy/Grype 共识）：crit/high→err 族（crit 靠 700 字重或实心 LED 区分，不新增第二红色相）、medium→warn 族、low→idle 族；**新增可选第四色相 info 蓝 `#0b5fce`** 专用于敏感路径/指纹发现的信息级条目，与品牌青色相距 42°（172° vs 214°），不撞强调色。每个状态色带 `-lo` 描边档与 `-bg` 淡底档，实色预配不做 rgba 混合；`--idle-lo` 与 `--info` 三档为纯增量新增（A 无此二档，B 补齐五族三档的完整矩阵）。
- **状态主档一色两用**：浅色下文字档与 LED 点用同一个主档值即可双双达标（字 ≥4.5:1，LED ≥3:1 非文字门槛全数以 ≥4.5 通过）——深色版需要"LED 禁放交互井底"的补丁规则，B 下该问题不存在，规则简化为"LED 只用主档实色"。

## Typography

**与方案 A 逐字共享，零分叉**（两案在同一套字体纪律上对比，评审变量只剩颜色与纵深）：

- **UI 字**（`--font-ui`）：Segoe UI / 微软雅黑 / 苹方。正文 13px、行高 1.55；页题/品牌 15px/600。
- **等宽字**（`--font-mono`）：ui-monospace / Cascadia Mono / Consolas。任务 ID、目标、URL、耗时、大小、时间戳、白名单条目、日志一律等宽。
- **等宽数字纪律**：一切 ID、计数、耗时、时间戳必须 `font-variant-numeric: tabular-nums`（`.mono` / `td.num` / `.chip` / `.logview` / `.stat-num` / `.pager-info` / `.wl-list` 已内建），800ms 轮询刷新列位不跳。**全站用高级属性 `font-variant-numeric`，禁低级 `font-feature-settings`**（嵌套元素第二次声明会整体替换继承列表）。
- **OpenType 特征（本轮经 font-features 技能 otfeat.py 实测两字体特征表，与上轮结论一致沿用）**：不启用 `zero`（Consolas 无此特征，跨机字形不一致）；不启用任何连字集 ss01–ss08/dlig（日志与路径必须字符原样，`->` 不能渲染成箭头）。
- **字号严格五档**：11 / 12 / 13 / 14 / 15px。禁止档外字号；数字要醒目靠字重与状态色，不靠放大。

## Layout

壳层与信息架构**与 A 完全共享**（本轮调研核对：同族五页桌面壳谱系，IA 参考 CyberStrikeAI 侧栏+分组导航思想，五页规模不启用分组折叠）：

- **壳层**：左 224px 侧栏（`--w-side`：品牌铭牌 + 五项导航带 `kbd` 快捷键提示 + 底部后端状态灯）+ 右主区；主区上 52px 顶栏（`--h-topbar`：页题 / Esc 停止提示 / 离线横幅挂点），100vh 单视口，无页面级滚动条叠加。
- **每页统一骨架公式**：view-title + 一句话副题 → stat 指标卡行（等宽大数字 + 小标签 + 语义色圆点）→ 分节标题 → 卡（卡头标题 + 卡头右侧内嵌筛选）→ 数据表。调研来源：CyberStrikeAI 数据页公式 + 现行 zcode 五页壳。
- **密度档（与 A 相同）**：数据表行高 ≈34px（`td` 上下 7px padding + 13px 基准），表头 11px + 0.06em 字距；面板间距 16px；主区水平留白 24px（`--pad-x`）；单视图最大 1080px（`--view-max`）。B 不做密度开关。
- **点阵坐标地板**：主区画布铺 24px 点阵底纹（`--dot-grid`，次文色 7% 透明度 1px 圆点——比深色版的 5% 略实，浅色下需要稍高透明度才可感知）；白面板浮于其上。窄窗（≤760px）关闭纹理。**低分屏莫尔纹检查列入 r2 待办（与 A 共担）。**
- **窄窗降级**：≤760px 侧栏收成 64px 图标轨（`--w-side-narrow`）。

## Elevation & Depth

浅色下的纵深 = **底色阶差 + 1px 发丝线 + 比深色版略实的贴面阴影**（白卡浮在灰画布上需要一点落地感，纯阶差在浅色下不足以把 s2 从画布上"抬"起来）：

- `--sh-1`（0 1px 2px 墨色 10%）：面板贴面，仅可感知的落地；禁扩散阴影。
- `--sh-2`（0 8px 24px 墨色 16%）：仅浮层（toast / 模态）保留。
- **凹井语义不变**：日志井沉到 `--s0`、输入井与 kbd 沉到 `--s1`、行悬停抬到 `--s3`——与深色版方向相反的明度、相同的空间逻辑。
- 禁止用阴影做层级堆叠；两级以上嵌套面板不允许 8px 圆角嵌 8px 圆角。

## Shapes

与 A 逐字相同：`--r-1` 3px（kbd）、`--r-2` 5px（按钮/输入框/提示框）、`--r-3` 8px（面板大卡）、`--r-full` 仅胶囊徽标与圆形 LED；面板 8px 内部控件一律 5px；**状态灯一律圆形**（圆形 LED 是两案共享的识别签名，禁方形）。

## Components

组件层全部在 `css/app.css`，选择器契约与 `index.html` / `js/**.js` 严格对齐（本轮 grep 实证：`app.css` 零裸色值、零 rgba()/hsl()、`index.html` 零内联 style、js 零 `.style.color` 赋值——组件层对 B 的全部颜色消费都经 `var()`，因此 B 的组件规格与 A 的差异**只在变量取值**，下表只列分叉点）：

- **面板（panel）**：白底 + `--ln-2` 边（浅色下面板边用 `--ln-2` 而非 `--ln-1`，1px 白卡在灰画布上需要可辨的边界）+ 8px 圆角 + 贴面阴影；面板头 `.panel-title` 前置 **14×2px 墨青刻度记号**（两案共享的签名元素，测距语言；墨青对面板 5.51:1）。
- **数据行三件套**：斑马纹（`--zebra` `#f7fafb`，比白底沉半档，实测阶差 1.05——浅色下斑马是"半调"而非深色版的"整档"，行分隔仍由 1px `--ln-1` 承担）；行悬停抬到 `--s3` 且首格点亮 2px `--acc-lo` 内轨（发丝 1.72:1，装饰性，可辨即可）；全局 `:focus-visible` 2px 墨青外圈（对面板 5.51:1，对画布 4.51:1，全表面过 3:1 焦点门槛）。
- **状态徽标（chip）**：胶囊描边态 + 圆点 LED——`created` 待命灰字 + idle-bg 淡底（6.46:1）、`running` 墨青亮档字 + `--acc-lo` 边 + LED 呼吸（唯一带动画的状态，1.6s 仅 opacity）、`done` 完成绿、`fail` 故障红、`stopped` 警示琥珀；设置页旗标走 `chip-lv-ok/-bad/-warn`。五档字色对各自底全部 ≥4.5:1。
- **按钮**：主按钮墨青底反白字（5.51:1，悬停 `--acc-hi` 底仍 4.72:1——深色版"悬停提亮、墨字不变"的行为在 B 下等价成立）；次按钮 `--s3` 井底主文字、悬停 `--s4`；停止按钮故障红字描边、悬停 err-bg 淡底；按压反馈 1px `translateY`。
- **LED（dot）**：8px 圆点，后端三态（online 绿 / offline 红 / checking 琥珀）与统计卡四态（total 灰 / running 墨青 / done 绿 / fail 红）全部用主档实色，对面板与骨架全部 ≥4.5:1。
- **toast**：`--s3` 井底 + `--sh-2`，进场 0.18s（opacity+translateY）；`toast-ok` 用 ok-bg 淡底 + 主文字、`toast-error` 用 err-bg 淡底 + 故障红字。**toast 只作状态回执（role=status），不承担确认交互**——不可逆操作走模态二次确认（焦点困住 + Esc 关闭）。
- **离线横幅**：warn-bg 淡底 + 警示琥珀字（5.09:1）+ role=alert + "立即重试"；出现时表单停用、每 5 秒自动重试。
- **图标**：只用 `index.html` 内手写线条风 SVG，八条硬参数与 A 相同（viewBox 24 / stroke=currentColor / fill=none，brand-mark 中心点唯一实心例外 / linecap+linejoin round / 描边 1.8、品牌 1.6 / 渲染 17px、品牌 30px / aria-hidden / 不引图标库）。`currentColor` 使图标自动跟随浅色文字三阶，无需任何改动。

## Do's and Don'ts

**Do：**

- 新颜色一律先进 `tokens.css`，组件层只写 `var()`；新状态色必须同时给出 `-lo` 描边档与 `-bg` 淡底档，且三档全部过本稿「无障碍」表列门槛。
- ID/计数/耗时/时间戳一律 `tabular-nums` 等宽排版；交互行三者齐备（斑马纹 / 悬停高亮+内轨 / 2px 墨青焦点环）。
- 动效只用 `opacity` / `transform`；尊重 `prefers-reduced-motion`（`app.css` 末尾全局兜底块不可移除）。
- 白卡边界靠 1px `--ln-2` + 贴面阴影；凹井靠底色阶差。

**Don't：**

- 禁止外链（网络字体 / CDN / `url()` 资源）、禁止裸色值进 `app.css`、禁止档外字号与档外间距、禁止方形状态灯、禁止对颜色/边框/填充做 transition 补间、禁止给墨青安排状态语义、禁止引用同类扫描器产品的具体样式值（以上全部与 A 共有）。
- **B 特有**：禁止在白底上用低于 `--ln-1` 对比度的颜色画功能性线条（浅色下发丝线容易消失）；禁止把 `-bg` 淡底当悬停色用（悬停一律 `--s3`，淡底只做状态底）；禁止在浅底上用深色版的状态色值（`#63bd80` 等对白底不足 4.5:1，跨案混用即违例）。

## 无障碍（实测数据）

以下数值全部经本会话 WCAG 相对亮度实算（`PYTHONUTF8=1 python %TEMP%/contrast_check_b.txt`，54 项门禁 **0 项未达标**，exit 0）：

- 主文 `--tx-1` 对 `--s0`–`--s4`：13.06 / 14.19 / 15.96 / 14.44 / 13.03:1；对斑马纹 15.22:1。
- 次文 `--tx-2` 对 `--s0`–`--s4`：6.00 / 6.52 / 7.33 / 6.63 / 5.99:1；对 idle-bg（created 徽章）6.46:1；日志字对日志井 6.00:1。
- 弱注 `--tx-3` 对 `--s0`–`--s4`：4.74 / 5.15 / 5.79 / 5.24 / **4.73**——**含强井全过 AA**（A 的对应短板 4.06:1）。
- 品牌墨青：主按钮白字对青底 5.51:1，对悬停底 `--acc-hi` 4.72:1；`--acc-hi` 作 running 徽章字对白底 4.72:1；焦点环/刻度记号对面板 5.51:1、对画布 4.51:1（焦点门槛 3:1）；墨青对 acc-bg 4.77:1。
- 状态色（字对面板 / 字对自身淡底 / LED 对面板与骨架，门槛 4.5/4.5/3.0）：ok 5.08/4.62/5.08·4.51；warn 5.68/5.09/5.68·5.05；err 5.67/5.02/5.67·5.04；idle 5.53/4.87/5.53·4.91；info 5.93/5.21/5.93·5.27。
- 发丝描边带（记录值，参考带 1.3–2.5）：`--ln-1/2/3` 1.33/1.54/1.99；ok-lo 1.94 / warn-lo 2.13 / err-lo 2.08 / idle-lo 1.63 / info-lo 1.79 / acc-lo 1.72。
- 淡底阶差（对面板）：acc-bg 1.16 / ok-bg 1.13 / warn-bg 1.12 / err-bg 1.13 / idle-bg 1.14 / info-bg 1.14；斑马 1.05。
- 色相间距：品牌青 172° 对 ok 137°（差 35°）、对 info 214°（差 42°）、对 warn 39°、对 err 357°——不撞强调色。
- `prefers-reduced-motion` 下全部动效压至 0.01ms（现有全局兜底块）；键盘焦点环全局 2px 墨青，按钮上内缩 1px。
- 遗留未验项（诚实申报）：`window.confirm` 在 WebView2 壳内的可用性、窄窗 ≤760px 与高 DPI 实机渲染、点阵纹理低分屏莫尔纹——三项均属 A/B 共担的 r2 待办，本轮未实机验证，不因选 B 而变化。

## 与方案 A 的关系与选型

**共享不变量（A/B 无分歧，不构成选型依据）：** 变量名契约 61 项、五页信息架构与 hash 路由 + Ctrl+1..5 + Esc 优先级键盘协议、页面骨架公式、密度档（34px 行高）、字号五档与等宽纪律、圆角/间距/布局尺寸、动效纪律与 reduced-motion 兜底、图标八条、圆形 LED 签名、零外链/零裸色值/零 AI 零对话组件的铁律。

**分叉点（选型依据）：**

| 维度 | A 深色「石板声呐」 | B 浅色「工程台」 |
|---|---|---|
| 底色模型 | 五级石板暗底，越内越亮 | 五级工程白底，白卡浮于灰画布、凹井下沉 |
| 品牌青 | 亮青 `#3cb8a8` 配暗墨字 | 墨青 `#0e7668` 反白字 |
| tx-3 弱注 | 禁上强井（4.06:1） | 全五级底过 AA（≥4.73:1） |
| 阴影 | 几乎不可感（黑 40% 贴面） | 略实（墨 10%/16%），撑起白卡 |
| LED 约束 | 待命灰禁放交互井底（2.92:1） | 无此约束（全 ≥4.5:1） |
| info 第四色相 | 需另配（上轮已给出深色三档） | 本稿内置三档 |

**场景建议**：多任务并盯、夜间值守为主 → A；以读表/比对/复制证据、报告与截图交付为主，或办公环境为白天亮室 → B。两案共享契约使选择**随时可逆**。

**双主题路线（可选后续，不在本稿范围）**：因 A/B 变量名一一对应，可用 `prefers-color-scheme` 挂两份 `:root` 值实现跟随系统双主题；代价是每个新状态色都要维护深浅两套三档并各自过对比度门禁——建议在 r2 之后再评估，本竞稿阶段不引入。

## 落地步骤（rollout）

1. **换肤即落地**：`B-tokens.css` 整文件替换 `frontend/css/tokens.css`（加载方式不变：app.css 顶部 `@import`）。**实证零改动面**：本轮 grep 显示 `app.css` 消费的 61 个变量全部在 B 中同名同义存在（`var(--…)` 清单核对），`app.css` 零裸色值、零 rgba()/hsl()、`index.html` 零内联 style——B 不触碰 `app.css` / `index.html` / `js/**` 任何一行。
2. **新增两枚增档变量**（`--idle-lo`、`--info` 三档）为纯增量；只有当发现页启用 info 语义时组件层才会消费，不启用则零影响。
3. **DESIGN.md 换版**：以本稿 front matter + 正文替换 `frontend/DESIGN.md`。本稿已过 lint：`npx -y -p @google/design.md designmd lint B-light-workbench.md` 实测 **0 错误 / 11 警告 / 1 信息**，警告全部为 `orphaned-tokens` 已知保留类（线阶 3 枚 + accent-lo + 五族 `-lo` 描边档 + info 族 3 枚——描边档在组件层 app.css 消费，design.md 组件属性白名单无边框槽位，与 A 的同类警告同源；落地替换后需对新文件复跑一次留档）。
4. **对比度回归**：落地后重跑本稿对比度脚本对 `frontend/css/tokens.css` 实际值复核（脚本以 .txt 随提案存档于本轮记录）。
5. **实机验收（r2 共担项）**：窄窗/高 DPI/低分屏莫尔纹/WebView2 实机截图走查，A/B 共用同一份验收清单。
6. **行为层改进不受选型影响**：本轮调研产出的 P0–P2 行为清单（列表分页、统计卡错态对齐、Esc 两段式停止、路由焦点管理、导出按钮终态禁用等 15 项）属 JS 行为，与 A/B 无关，按既有节奏另行落地。

## 风险与不适用场景

- **夜间/低光值守不友好**：暗室里白底刺眼，长时间夜间并盯的用眼成本高于 A——这是 B 的主要让步，若团队以夜班值守为主应选 A。
- **浅色发丝线更脆弱**：行分隔/描边档在低质量面板或色彩管理偏差的屏幕上比深色版更容易不可见；已把发丝带下限定在 1.3（`--ln-1` 1.33），但低分屏实机复核未做。
- **截图一致性**：深色终端/深色代码截图贴进本工具白底面板时反差强烈（如详情页外链报告、终端复现场景）；B 不处理内嵌深色内容的美化，只能靠"外链查看"规避。
- **莫尔纹与高 DPI 未验**：点阵地板与发丝线在低分屏的表现属两案共担的 r2 待办，本轮未实机验证。
- **双主题诱惑**：B 落地后最可能的范围蔓延是"顺手做双主题"；本稿明确将其划出范围（见「与方案 A 的关系」），需单独立项过对比度双倍维护成本这一关。
- **本稿未经实机渲染验证**：全部数值结论来自 WCAG 实算与静态 grep 核对，未启动应用截图走查（与竞稿阶段定位一致，落地步骤 5 补齐）。
