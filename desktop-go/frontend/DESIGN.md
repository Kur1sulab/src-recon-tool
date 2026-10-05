---
version: alpha
name: Slate Sonar
description: 信息收集工具（src-recon-tool 桌面端）的深色控制室视觉体系终稿——冷蓝石板底、青鹤唯一强调、圆形声呐 LED、等宽数据列、斑马纹数据行、应用内确认面板；纯本地无 AI，零联网模型调用、零遥测上报。
colors:
  primary: "#3cb8a8"
  secondary: "#9aabb9"
  tertiary: "#63bd80"
  neutral: "#151f28"
  canvas: "#0c1116"
  chrome: "#101820"
  well: "#1b2732"
  well-strong: "#223040"
  zebra: "#121b23"
  line-hair: "#1e2b36"
  line-card: "#273745"
  line-hover: "#354857"
  text-primary: "#dee6ec"
  text-secondary: "#9aabb9"
  text-muted: "#7a90a4"
  accent-hi: "#74d6c7"
  accent-lo: "#1d4a43"
  accent-ink: "#04201b"
  accent-bg: "#102e2b"
  status-ok: "#63bd80"
  status-ok-lo: "#2a5c3c"
  status-ok-bg: "#15271d"
  status-warn: "#d9a353"
  status-warn-lo: "#6b5426"
  status-warn-bg: "#2a2216"
  status-bad: "#e07b6c"
  status-bad-lo: "#6e3a33"
  status-bad-bg: "#2c1d1a"
  status-idle: "#5b6f82"
  status-idle-bg: "#131c24"
  scrim: "rgba(0, 0, 0, 0.55)"
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
    backgroundColor: "{colors.neutral}"
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
  confirm-scrim:
    backgroundColor: "{colors.scrim}"
  confirm-box:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
---

## Overview

「信息收集工具」（工程名 src-recon-tool）是纯本地（127.0.0.1）的授权目标信息收集桌面客户端：子域枚举、资产测绘、指纹识别、敏感路径、API 面梳理；无 AI 功能、无联网模型调用、无遥测上报，数据不出本机。五个页面：任务列表 / 新建任务 / 任务详情 / 证据包 / 设置。界面的主要内容是 800ms 轮询的实时遥测（任务状态、模块进度、原始日志尾）。

**主题裁决（终稿）**：深色「石板声呐 Slate Sonar」是**唯一**规范主题。浅色工作台（B 方案）与双主题机制（C 方案）均不落地——不加 `data-theme` 属性、不加 `js/theme-boot.js`、不加任何主题 localStorage 键、设置页不加「界面主题」行。浅色主题作为 r2 后议题登记在「缓议登记」节，立项需同时满足真实用户需求、双值维护承诺、5 页 × 2 主题实机走查矩阵三个门槛。

**为什么是深色控制室，而不是浅色工程台：**

1. **内容本质是实时遥测，不是文档。** 界面的核心阅读动作是持续监视与状态扫读（运行中的 LED 呼吸、模块进度行入账、日志尾滚动），这是控制室仪表盘的阅读模式；浅色工程台擅长静态批注与精细研读，与本客户端的值守场景错位。
2. **终端原生内容在暗底上才协调。** 任务 ID、目标、URL、耗时、文件大小、时间戳全部走等宽字体（`--font-mono`）+ `tabular-nums`；等宽终端语汇放在浅色图纸上会割裂。
3. **与同类作业面板同族不同貌。** 本体系是**冷蓝相石板底 + 青鹤强调 + 圆形 LED + 刻度记号**的取值体系，与石墨中性底 + 琥珀强调 + 方形 LED 体系、绿字终端类及黑底白字类扫描器产品均无任何样式值引用关系（严禁照抄任何同类产品样式）。
4. **长时间值守的用眼成本。** 一轮信息收集数分钟起步，多任务并盯时暗底低亮度更可持续。

**动效纪律（硬约束）：** `animation`/`transition` 只允许 `opacity` 与 `transform` 两个通道；持续动画全站仅 LED 呼吸一种（1.6s、仅 opacity）；进场动画 ≤180ms、位移 ≤6px（toast 与确认面板共用 `toast-in` 0.18s）；颜色、边框、填充类状态一律即时切换、不做补间（按钮悬停即时换色、按压走 `translateY(1px)`）。全部动效在 `prefers-reduced-motion: reduce` 下压至 0.01ms（app.css 末尾全局兜底块，不可移除；LED 呼吸在 reduce 下退化为常亮圆点，状态仍由颜色区分）。

## Colors

全部颜色只存在于 `css/tokens.css`（唯一颜色来源），组件层 `css/app.css` 禁止裸色值；验收门禁即 `grep -nE '#[0-9a-fA-F]{3,8}\b|rgb\(|hsl\(' frontend/css/app.css` 零命中。

- **石板五级底（`--s0`→`--s4`）**：画布 `#0c1116` → 骨架 `#101820` → 面板 `#151f28` → 交互井 `#1b2732` → 强井 `#223040`。冷蓝相（hue≈210），纵深全靠阶差，不靠阴影堆叠。
- **精密边框三阶（`--ln-1/2/3`）**：行发丝线 / 卡片边 / 悬停边，全部 1px。
- **文字三阶（`--tx-1/2/3`）**：冷蓝灰 `#dee6ec` / `#9aabb9` / `#7a90a4`。弱注档 `--tx-3` 实测对 `--s0`–`--s3` 全部 ≥4.5:1（过 WCAG AA），不设"注脚豁免"。
- **品牌青鹤（`--acc` 族）**：`#3cb8a8` 是全站唯一强调色，只用于——焦点环、激活轨、刻度记号、主按钮底、运行态。绝不参与状态语义（绿=完成、橙=警示、红=故障已占用）。
- **状态色族（`ok` / `warn` / `err` + `idle`）**：磷光绿 `#63bd80`（完成/在线）、信号橙 `#d9a353`（停止/警示）、故障红 `#e07b6c`（失败/离线）、待命灰 `#5b6f82`（已创建/后端连接中）。每个状态色带 `-lo` 描边档与 `-bg` 淡底档，预配为实色（不做 rgba 混合，保证零色值泄漏到组件层）。风险分级惯例对齐安全工具共识（crit/high→红、medium→橙、low→灰、unknown→中性描边）：crit/high 复用 err 族靠 700 字重或实心 LED 区分，不新增第二红色相；medium→warn 族；low→idle 族。
- **遮罩（`--scrim`）**：`rgba(0,0,0,0.55)`，应用内确认面板全屏遮罩专用（消费者 `.confirm-scrim`）。
- **新颜色准入流程（硬规则）**：新色一律先进 `tokens.css`、同步本文件 front matter，并重跑对比度脚本全过后才准进组件层；无消费者的候选值只能留在「预配色库」节，不得进令牌。
- **描边档说明**：`design.md` front matter 的组件属性白名单没有边框槽位，`-lo` 描边档与 `line-*` 线阶在组件层 `app.css` 消费；lint 实测 `orphaned-tokens` 警告 8 枚（`line-hair` / `line-card` / `line-hover` / `accent-lo` / `status-ok-lo` / `status-warn-lo` / `status-bad-lo` / `status-idle-bg`，0 错误，exit 0），全部属「无边框槽位」的已知保留类，不作修复。

**对比度硬边界（WCAG 实测红线，违者返工）：**

1. `--tx-3 #7a90a4` 对 `--s4 #223040` 仅 **4.06:1**，不过 AA——**弱注档禁上强井**，凡落在 s4 上的文字至少用 `--tx-2`（对 s4 实测 5.69:1）。
2. `--idle #5b6f82` LED 对 `--s3 #1b2732` 仅 **2.92:1**，不过 3:1 非文字门槛——**待命灰圆点禁放交互井底**，只能对 s2（3.21:1）或 idle-bg（3.31:1）。
3. `--idle` **不作文字色**（对 `--s2` 仅 3.21:1，只够图形档，不够 AA 文字档）。
4. `-lo` 描边档**只描边、禁作文字色**（对 s2 在 1.84–2.32 发丝级，与 `--ln-2` 1.37 同族）。

## Typography

系统字体栈，零外链（无网络字体、无字体文件）：

- **UI 字**（`--font-ui`）：Segoe UI / 微软雅黑 / 苹方。正文 13px、行高 1.55；页题/品牌 15px/600。
- **等宽字**（`--font-mono`）：ui-monospace / Cascadia Mono / Consolas。任务 ID、目标、URL、耗时、大小、时间戳、白名单条目、日志一律等宽。
- **等宽数据列（硬规则）**：一切 ID、计数、耗时、时间戳必须 `font-variant-numeric: tabular-nums`（`.mono` / `td.mono` / `td.num` / `.chip` / `.logview` / `.stat-num` / `.pager-info` / `.wl-list` 内已内建），800ms 轮询刷新时列位不跳。长 URL/长路径在数据列内 `overflow-wrap: anywhere` 折行。
- **字体特征纪律（按 otfeat.py 对 CascadiaMono.ttf / consola.ttf 实测特征表）**：
  - 全站只用高级属性 `font-variant-numeric`，**禁低级 `font-feature-settings`**——后者全量替换继承列表，嵌套元素二次声明会静默丢失前级特征；
  - **不启用 `zero`**（斜杠零）——Consolas 无此特征，跨机字形不一致；两字体默认零形均已与字母 O 区分；
  - **不启用任何连字集（ss01–ss08 / dlig）**——日志与路径必须字符原样，`->` 不能渲染成箭头；
  - `tnum` 对纯等宽字体是无操作（front matter 留作护栏声明），真正的纪律是数字必须落在等宽字体元素内。
- **字号严格五档**：11 / 12 / 13 / 14 / 15px（`--fs-11`…`--fs-15`），档外禁用，不再新增档位。固定映射：11=表头/kbd/铭牌，12=徽标/日志/脚注，13=正文基准（表数据），14=输入框，15=页题/统计大数字。数字要更醒目靠字重与状态色，不靠放大字号。
- **行高三档**：1.4（标题/徽标）/ 1.55（正文）/ 1.6（日志/等宽数据）。

## Layout

- **壳层**：左 224px 侧栏（`--w-side`，五项导航 + 品牌铭牌 + 底部后端状态灯）+ 右主区；主区上 52px 顶栏（`--h-topbar`：页题 / Esc 提示），下为滚动主面板（水平留白 `--pad-x` 24px）。
- **点阵坐标地板**：主面板铺 24px 点阵底纹（`--dot-grid`，次文色 5% 透明度的 1px 圆点）；内容面板浮于其上。窄窗（≤760px）关闭纹理（低分屏莫尔纹待 r2 实机复核）。
- **密度档（唯一）**：数据表行高 ≈34px（`td` 上下 7px padding + 13px 基准字号），表头 11px 加 0.06em 字距；面板间距 16px。
- **间距体系**：4px 网格 `--sp-1..6` = 4/8/12/16/20/24px；组件内 6/7/9/10px 属行内 padding 细节，不算档位。
- **窄窗降级**：≤760px 侧栏收成 64px 图标轨（`--w-side-narrow`），隐藏导航文字/快捷键/铭牌，内容区关闭点阵纹理，统计卡降为两列。
- **内容宽**：单视图最大 1080px（`--view-max`）。

## Elevation & Depth

纵深主要靠**底色阶差 + 1px 精密线**，阴影只做贴面：

- `--sh-1`（0 1px 2px 黑 40%）：面板贴面，几乎不可感的落地。
- `--sh-2`（0 6px 24px 黑 45%）：仅浮层保留——toast 与确认面板。
- `--scrim`（黑 55%）：仅确认面板全屏遮罩（`.confirm-scrim`）。
- **凹井**：日志视图、输入井沉到更深的底色（日志 `--s0`、输入 `--s1`），形成"面板上的凹井"。

## Shapes

- **近直角仪表取向**：`--r-1` 3px（kbd）、`--r-2` 5px（按钮/输入框/提示框）、`--r-3` 8px（面板大卡）、`--r-full` 仅用于胶囊徽标与圆形 LED。
- **层级规则**：面板 8px 内部控件一律 5px，**不允许 8px 嵌 8px**。
- **圆形声呐 LED**：状态灯、白名单条目前点全部是圆形小点——声呐定位语汇，是本体系的识别签名，**禁方形**。
- **SVG 线条图标八条硬参数**（`index.html` 内手写，不引图标库，零外链）：
  1. `viewBox="0 0 24 24"`；
  2. `stroke="currentColor"`（颜色随文字档继承）；
  3. `fill="none"`（唯一实心例外：brand-mark 中心点 `fill="currentColor"`）；
  4. `stroke-linecap="round"`；
  5. `stroke-linejoin="round"`；
  6. 描边宽两档——导航/功能图标 **1.8**，品牌标 **1.6**；
  7. 渲染尺寸两档——导航 17px，品牌 30px；
  8. 一律 `aria-hidden="true"`。新增图标照此八条手写。

## Components

组件层全部在 `css/app.css`，选择器契约与 `index.html` / `js/**` 严格对齐（CSP 禁内联样式，动态状态全部走 class/data 属性；类名契约全表见「类名契约」节）。

- **面板（panel）**：`--s2` 底 + `--ln-1` 边 + 8px 圆角 + 贴面阴影；面板头 `.panel-title` 前置 **14×2px 青色刻度记号**（本体系签名元素，测距语言）。
- **数据行三件套**：
  - **斑马纹**：`table.data` 偶数行铺 `--zebra`（比面板底沉半档）；表头行不参与。
  - **悬停高亮**：行悬停抬到 `--s3` 交互井，且首格点亮 2px 暗青内轨（`inset 2px 0 0 var(--acc-lo)`，box-shadow 即时切换）。
  - **清晰焦点环**：全局 `:focus-visible` 为 2px 品牌青外圈（offset 2px；按钮上内缩为 1px 防裁切）。切页后焦点移页题（`#viewTitle` 补 `tabindex="-1"`，由结构线落地；编程聚焦落在全局焦点环上）。
- **表格可及性**：`caption` + `th scope="col"` + 行内按钮 `aria-label` 带行上下文（如「查看任务 a1b2c3d4」），由结构线落地。
- **状态徽标（chip）**：胶囊描边态 + 圆点 LED，按 `data-s` 五态契约着色——`created` 待命灰（tx-2 字 + idle-bg 淡底）、`running` 亮青字 + LED 呼吸（唯一带动画的状态，`breathe` 1.6s 仅 opacity）、`done` 磷光绿、`fail` 故障红、`stopped` 信号橙；`data-s` 未匹配即中性描边兜底态；设置页旗标走 `chip-lv-ok/-bad/-warn`。新增状态先加 `data-s` 值再进 CSS。
- **按钮**：主按钮青底墨字、次按钮石板井、停止按钮故障红描边；按压反馈为 1px `translateY` 位移（transform 通道），悬停即时换色不补间；提交中态文案「提交中…」由行为线切换。
- **LED（dot）**：8px 圆点，后端状态三态（online 绿 / offline 红 / checking 橙）复用同族；LED 只对 s1/s2/idle-bg 底合法，禁放 s3 井底（硬边界 2）。
- **toast**：`--s3` 井底 + `--sh-2`，进场 `toast-in` 0.18s（opacity+translateY 6px）；文案统一带 8 位短 id（如「停止指令已提交（任务 xxx）」）。
- **应用内确认面板（confirm）**：破坏性操作（删除任务）的应用内确认，替代原生 `confirm()`。`.confirm-scrim` 全屏遮罩（`--scrim`）+ `.confirm-box` 居中小面板（`--s2` 底 / 8px 圆角 / `--sh-2`，进场复用 `toast-in`）；内部复用 `.panel-title` 与 `.btn`/`.btn-danger`，不新增第三层类。标题含短 id 与目标，正文写后果说明，取消/确认双键；焦点困住、Esc 关闭、确认中禁点由行为线落地。
- **离线横幅**：warn 族三档（字/底/边），「立即重试」复用 `.btn`，零新增类。
- **分页器**：`.pager` / `.pager-info`（已存在，零新增）；PAGE=50，页码跨轮询保持，轮询只刷当前页。

## Do's and Don'ts

**Do：**

- 新颜色一律先进 `tokens.css`，组件层只写 `var()`；同步本文件 front matter 并重跑对比度脚本。
- 新状态色必须同时给出 `-lo` 描边档与 `-bg` 淡底档，并过同门槛实测。
- ID/计数/耗时/时间戳一律 `tabular-nums` 等宽排版。
- 交互行必须三者齐备：斑马纹 / 悬停高亮+内轨 / 2px 青色焦点环。
- 动效只用 `opacity` / `transform`；持续动画全站 ≤1 种；进场 ≤180ms、位移 ≤6px；尊重 `prefers-reduced-motion`（app.css 末尾兜底块不可移除）。
- 图标只用 `index.html` 内手写线条风 SVG，严守八条硬参数。
- 新组件先在「类名契约」节登记类名再写样式。

**Don't：**

- 禁止外链：无网络字体、无 CDN、无 `url()` 资源引用。
- 禁止裸色值进 `app.css`（含 rgba/hsl 写法）；禁止内联 `style` 属性；禁止 JS `.style.color` 赋值。
- 禁止给青鹤安排状态语义（它是唯一品牌强调色，不是状态色）。
- 禁止档外字号、档外间距、方形状态灯、8px 嵌 8px。
- 禁止对颜色/边框/填充做 transition 补间。
- 禁止 `font-feature-settings` 低级声明；禁启用 `zero` 与一切连字集。
- `--tx-3` 禁上 `--s4`；`--idle` 禁作文字色、其 LED 禁放 `--s3` 井底；`-lo` 档禁作文字色。
- 无消费令牌禁入 `tokens.css`（候选值留「预配色库」）。
- 禁止引用/照抄任何同类扫描器、终端产品的具体样式值。
- 用户可见文案禁出现旧产品名；页面名用「新建任务」。

## 无障碍

以下数值全部经 WCAG 相对亮度实算（本轮门禁脚本复跑，存档 `%TEMP%/r3_contrast_gate.txt`）：

- 主文 `--tx-1 #dee6ec` 对画布 `--s0` 15.02:1，对面板 `--s2` 13.2:1。
- 次文 `--tx-2 #9aabb9` 对 `--s0`–`--s3` 6.4–8.0:1；对 `--s4` 5.69:1（强井上的文字下限档）。
- 弱注 `--tx-3 #7a90a4` 对 `--s0`–`--s3` 5.74 / 5.41 / 5.05 / 4.59，全档过 AA（旧值 `#71879a` 对面板 4.48:1 不达标，r1 提亮修正）；对 `--s4` **4.06:1 不过**（硬边界 1）。
- 品牌青 `#3cb8a8` 对面板 6.8:1；亮青 `#74d6c7` 对面板 9.7:1；主按钮墨字 `--acc-ink #04201b` 对青底 7.0:1。
- 状态字对面板：绿 7.25:1、橙 7.40:1、红 5.74:1；对各自 `-bg` 淡底 6.81 / 6.96 / 5.56，全部过 AA。
- 待命灰：LED 对 `--s2` 3.21:1、对 `--idle-bg` 3.31:1（过 3:1 非文字门槛）；对 `--s3` **2.92:1 不过**（硬边界 2）；作文字对 `--s2` 仅 3.21:1 不达 AA（硬边界 3）。
- 表头用 `--tx-2`（对 s2 7.07:1），不用弱注档。
- `-lo` 描边档对 s2 在 1.84–2.32 发丝级，与 `--ln-2` 的 1.37 同族，只作描边（硬边界 4）。
- 遮罩 `--scrim` 为半透明叠层，非文字底，不作对比度门槛对象；其下内容以 `.confirm-box` 实底 `--s2` 承载文字（tx-1 对 s2 13.2:1）。
- `prefers-reduced-motion` 下全部动效压至 0.01ms；键盘焦点环全局 2px 青色。

## 类名契约

命名规则：BEM-lite 单层——`.块`、`.块-子件`、`.块-修饰`；状态一律优先 data 属性；JS 动态类仅限既有契约名 `hidden` / `warn` / `active`；JS 拼 className 允许「基类+变体」字面量（`.dot` 拼 offline/onli*、`.toast` 拼 ok/err）；禁止内联 style、禁止 JS `.style.color` 赋值。新组件先在本节登记类名再写样式；改名须同步本文件；界面施工员改结构前须对照本清单；美术新增选择器不得超出契约命名规则（禁驼峰、禁下划线、禁深层嵌套选择器）。

- **壳层**：`.app` `.sidebar` `.side-nav` `.side-foot` `.side-note` `.brand` `.brand-mark` `.brand-name` `.brand-sub` `.brand-text` `.topbar` `.topbar-side` `.main` `.content` `.view` `.view-title` `.hidden`
- **导航与状态**：`.nav-item`（active 态由 `classList.toggle("active")` 驱动）`.backend-status` `.dot`（offline|online|checking 由 JS 拼）`.esc-hint` `.offline-banner`
- **页面骨架**：`.stat-row` `.stat-card`（`data-k=total|running|done|fail`；`data-stale="true"` 为离线回落灰显）`.stat-num` `.stat-label` `.panel` `.panel-head` `.panel-title` `.panel-actions` `.panel-foot` `.table-wrap` `.empty-hint` `.kv-grid` `.pipeline-note` `.task-picker`
- **数据与徽标**：`.chip` + `data-s` 五态（`created|running|done|fail|stopped`，未匹配为中性兜底）`.chip-lv-ok` `.chip-lv-bad` `.chip-lv-warn`（设置页旗标）`td.mono` `td.num` `.mono` `.data` `.pager` `.pager-info` `.logview`
- **表单与反馈**：`.form-row` `.form-actions` `.form-error` `.field-hint` `.submit-note` `.opt-mark` `.input` `.btn` `.btn-primary` `.btn-danger` `.toast`（ok|err 变体）`.warn`（JS 动态）
- **白名单盒**：`.whitelist-box` `.wl-title` `.wl-list` `.wl-note` `.wl-loading`
- **本轮新增**：`.confirm-scrim`（全屏遮罩，`--sh-2`/`--scrim` 语义）`.confirm-box`（居中小面板，`--r-3`/`--s2` 底，内部复用 `.panel-title` 与 `.btn`/`.btn-danger`，不新增第三层类）；状态筛选 select 复用 `.input`；离线横幅「立即重试」复用 `.btn`（均零新增类）
- **禁改清单**：以上类名与 `.chip[data-s]` 契约为结构-样式共同契约。若未来启用行详情抽屉（缓议），届时先在本节登记 `.drawer` `.drawer-head` `.drawer-close` 再进 CSS。

## 文案字库

用户可见文案中文大白话，产品名一律「信息收集工具」，页面名「新建任务」；窗口标题/侧栏铭牌/关于页/文档同口径。

**三态句式模板：**

- 空态：「还没有X。到「Y」去Z。」
- 载态：「正在加载X…」
- 离线：「离线：无法获取X，本地服务恢复后将自动刷新。」
- 失败：「X获取失败：<原因>」

**状态词表（chip 五态 + 后端三态，模块级与任务级同词）：**

- `created`＝待开始（不用「已创建」；停止按钮 title 说明「尚未运行也可停止」）
- `running`＝运行中（唯一呼吸动画状态）
- `done`＝已完成（模块级同词）
- `fail`＝失败
- `stopped`＝已停止
- 未知状态＝中性描边兜底
- 后端：online 在线 / offline 离线 / checking 连接中

**toast 统一带 8 位短 id**：「停止指令已提交（任务 xxx）」。退出码附中文判读（如「0（正常结束）」）。

## 五页逐页要点

1. **任务列表**：4 统计卡（总/运行中青点呼吸/完成绿/失败红），错态时统计卡同步回落灰显（`data-stale`）并标注「数据为离线前旧值」；6 列表（短 id mono/目标 mono/子命令 chip/状态 chip/创建时间 mono/操作）；「创建时间」列固定取 `created_at`，缺失显示「—」；卡头右侧状态筛选 select（复用 `.input`）+ PAGE=50 分页（轮询只刷当前页，页码跨轮询保持）；删除走应用内确认面板（`.confirm-scrim`/`.confirm-box`）；行内按钮（查看/停止/重开/删除/证据包）一律带行上下文 `aria-label`。
2. **新建任务**：提交按钮文案变「提交中…」失败还原；监听离线恢复自动重载白名单并清提示；白名单注释统一为「用户自有资产（已授权）」；保留目标↑↓历史回填、模块 kind 提示（warn 族文字，落 `.field-hint.warn`）、`form-error role=alert`。
3. **任务详情**：四段式（元信息 kv-grid+操作区→模块进度表→产物表→日志尾）；模块级 `done` 统一「已完成」；退出码附中文判读；停止 toast 带短 id；模块进度表载态「正在加载任务详情…」；日志尾刷新判据「长度+末行指纹」，距底 48px 内才跟随；PAGE=50 分页页码跨轮询保持。
4. **证据包**：任务选择器加载前先插「加载任务列表…」载态 option；产物表对齐 PAGE=50+分页器；导出按钮 `created`/`running` 时禁用并注明「任务结束后可导出」；保留路径注记行。
5. **设置**：三分组——运行环境自检（kv-grid+「运行自检」按钮，先渲染「正在检测运行环境…」载态；env 拉取失败≠Python 未安装，两态分开）/授权目标白名单（只读 mono 表+403 硬闸脚注）/关于（产品名「信息收集工具」、版本、定位一句话：专精信息收集——子域枚举/资产测绘/指纹识别/敏感路径/API 面梳理；纯本地声明：无 AI 功能、无联网模型调用、无遥测上报、数据不出本机）。**不加主题切换行**；mock 靶站联调文案收进运行环境组开发子项。

## 预配色库（已实测候选值，进令牌前必须有消费页）

本轮令牌收紧：以下候选值**实测过门槛但不入 `tokens.css`**——出现真实消费页后，按「先进 tokens.css → 再进 front matter → 重跑对比度脚本」流程迁入。

- **info 蓝族（第四状态色相候选）**：`--info: #5aa9e6` / `--info-lo: #2e4d66` / `--info-bg: #11222e`。实测：info 对 s2 6.56:1（AA 文字）、对 info-bg 6.39:1、tx-1 对 info-bg 12.88:1、info-lo 对 s2 1.88（落在 -lo 家族带 1.84–2.32）、info-bg 对 s2 1.03（与现有 -bg 档 1.03–1.06 一致）；与品牌青色相相距 34°（172° vs 206°），不撞强调色。触发场景：敏感路径/指纹结果需要与 ok/warn/err/idle 区分的第四语义时。
- **严重度别名组（`--sev-*`）**：crit/high→err 族、medium→warn 族、low→idle 族（`--sev-low-lo` 暂以 `--ln-3` 充当）、info→info 族。别名只是映射表，不新增色相；crit 靠 700 字重或实心 LED 与 high 区分。落地前必须有消费页（如指纹/路径结果分级列）。
- **`--w-drawer: 460px`（及 `--w-drawer-max: 60vw`）**：行详情抽屉宽度候选。抽屉未立项（缓议），令牌不入；立项时先在「类名契约」登记 `.drawer` 三件套。
- **`--idle-lo`**：待命灰描边档候选，本轮实证零消费，**不入令牌**；idle 族边线需求一律走 `--ln-3`，此为本文件成文例外。

## 验收门禁（样式线落地必跑）

1. `grep -nE '#[0-9a-fA-F]{3,8}\b|rgb\(|hsl\(' frontend/css/app.css` 零命中。
2. `grep -n 'style="' frontend/index.html` 零命中。
3. 对比度脚本全过 + 两条硬边界复现（本轮回归底稿 `%TEMP%/r3_contrast_gate.txt`）。
4. 新增文件 UTF-8 编码。
5. webapp-testing 真开页面走查（窗口标题/侧栏铭牌「信息收集工具」、导航「新建任务」、前端三文件 grep 旧产品名零命中）+ 窄窗/高 DPI/低分屏莫尔纹实机复核——属视觉验收线 r2 共担待办，样式线自查只覆盖文案 grep 项。

## 缓议登记

- **浅色主题立项评估**（r2 后议题）：输入材料＝B 方案 tokens.css 候选值（tx-3 全底过 AA 的深文字档思路）+ C 方案 data-theme 机制设计与 theme-boot.js 无闪烁方案；立项门槛＝真实用户需求 + 双值维护承诺 + 5 页 × 2 主题实机走查矩阵。
- **行详情抽屉**：`.drawer` 三件套与 `--w-drawer` 待真实需求立项。
- **视觉 r2 待办**：空态精细化、长 URL 折行复核、耗时列微图表（纯 CSS）、窄窗/高 DPI 实机复核、低分屏点阵莫尔纹检查、对比度全量回归。

## 三轮路线图

- **视觉轮 r1**：定体系——深色控制室论证、tokens.css 建立、app.css 全量重写、DESIGN.md 按 Google design.md 规范成文。
- **视觉轮 r2**：空态/折行/微图表/窄窗/高 DPI/莫尔纹/对比度回归（待办，见「缓议登记」）。
- **视觉轮 r3（本轮，终稿）**：主题裁决收口（石板声呐唯一，B/C 不落地）；令牌收紧（--info/--sev-*/--w-drawer/--idle-lo 转入预配色库，--scrim 因确认面板消费准入）；app.css 全量重写（契约类名全覆盖 + 五页段落 + `.confirm-scrim`/`.confirm-box` 新组件 + 离线横幅按钮位 + 筛选 select 行内宽适配）；DESIGN.md 按规范节序重组并落硬边界/类名契约/文案字库/五页要点/验收门禁；lint（Windows 安全别名 `npx -y -p @google/design.md designmd lint DESIGN.md`）留档，orphan 警告为已知保留。
