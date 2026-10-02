---
version: alpha
name: Slate Sonar
description: 侦察工作台（src-recon-tool 桌面端）的深色控制室视觉体系——冷蓝石板底、青鹤唯一强调、圆形声呐 LED、等宽数据列、斑马纹数据行。
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
---

## Overview

「侦察工作台」是纯本地（127.0.0.1）的授权目标侦察桌面客户端：任务列表 / 新建侦察 / 任务详情 / 证据包 / 设置五页，800ms 轮询的实时遥测（任务状态、模块进度、原始日志尾）是其主要内容。视觉体系在视觉轮 r1 正式定为 **深色控制室 · 石板声呐（Slate Sonar）**——冷蓝石板五级底、青鹤色唯一强调、圆形声呐 LED、等宽数据列、斑马纹数据行。

**为什么是深色控制室，而不是浅色工程台：**

1. **内容本质是实时遥测，不是文档。** 界面的核心阅读动作是持续监视与状态扫读（运行中的 LED 呼吸、模块进度行入账、日志尾滚动），这是控制室仪表盘的阅读模式；浅色工程台擅长静态批注与精细研读，与本客户端的值守场景错位。
2. **终端原生内容在暗底上才协调。** 任务 ID、目标、URL、耗时、文件大小、时间戳全部走等宽字体（`--font-mono`）+ `tabular-nums`；等宽终端语汇放在浅色图纸上会割裂。
3. **与用户的漏扫作业台同族不同貌。** 两者同为桌面安全作业面板，共用「深色控制室」的家族基因（多级暗底 + 单一品牌强调 + 状态色只做语义不做装饰 + 等宽数据纪律），但本体系换成**冷蓝相石板底 + 青鹤强调 + 圆形 LED + 刻度记号**，与其石墨中性底 + 琥珀强调 + 方形 LED 的具体取值体系明确区分；与绿字终端类及黑底白字类扫描器产品亦无任何样式值引用关系。
4. **长时间值守的用眼成本。** 一轮侦察数分钟起步，多任务并盯时暗底低亮度更可持续。

**动效纪律（硬约束）：** `animation`/`transition` 只允许 `opacity` 与 `transform` 两个通道（LED 呼吸、toast 进场、按钮按压位移）；颜色、边框、填充类状态一律即时切换、不做补间。全部动效在 `prefers-reduced-motion: reduce` 下压至 0.01ms。

## Colors

全部颜色只存在于 `css/tokens.css`（唯一颜色来源），组件层 `css/app.css` 禁止裸色值。

- **石板五级底（`--s0`→`--s4`）**：画布 `#0c1116` → 骨架 `#101820` → 面板 `#151f28` → 交互井 `#1b2732` → 强井 `#223040`。冷蓝相（hue≈210），纵深全靠阶差，不靠阴影堆叠。
- **精密边框三阶（`--ln-1/2/3`）**：行发丝线 / 卡片边 / 悬停边，全部 1px。
- **文字三阶（`--tx-1/2/3`）**：冷蓝灰 `#dee6ec` / `#9aabb9` / `#7a90a4`。弱注档 `--tx-3` 实测对 `--s0`–`--s3` 全部 ≥4.5:1（过 WCAG AA），不设"注脚豁免"；`--tx-3` 不上 `--s4` 强井。
- **品牌青鹤（`--acc` 族）**：`#3cb8a8` 是全站唯一强调色，只用于——焦点环、激活轨、刻度记号、主按钮底、运行态。绝不参与状态语义（绿=完成、橙=警示、红=故障已占用）。
- **状态色族（`ok` / `warn` / `err` + `idle`）**：磷光绿 `#63bd80`（完成/在线）、信号橙 `#d9a353`（停止/警示）、故障红 `#e07b6c`（失败/离线）、待命灰 `#5b6f82`（已创建/后端连接中，LED 对面板 ≥3:1 非文字门槛）。每个状态色带 `-lo` 描边档与 `-bg` 淡底档，预配为实色（不做 rgba 混合，保证零色值泄漏到组件层）。
- **描边档说明**：`design.md` front matter 的组件属性白名单没有边框槽位，`-lo` 描边档与 `line-*` 线阶（7 枚）在组件层 `app.css` 消费，lint 的 `orphaned-tokens` 警告（0 错误 7 警告）即来源于此，属已知保留。

## Typography

系统字体栈，零外链（无网络字体、无字体文件）：

- **UI 字**（`--font-ui`）：Segoe UI / 微软雅黑 / 苹方。正文 13px、行高 1.55；页题/品牌 15px/600。
- **等宽字**（`--font-mono`）：ui-monospace / Cascadia Mono / Consolas。任务 ID、目标、URL、耗时、大小、时间戳、白名单条目、日志一律等宽。
- **等宽数字纪律**：一切 ID、计数、耗时、时间戳必须 `font-variant-numeric: tabular-nums`（`.mono` / `td.num` / `.chip` / `.logview` 内已内建），800ms 轮询刷新时列位不跳。
- **字号严格五档**：11 / 12 / 13 / 14 / 15px（`--fs-11`…`--fs-15`）。禁止档外字号。

## Layout

- **壳层**：左 224px 侧栏（`--w-side`，五项导航 + 品牌铭牌 + 底部后端状态灯）+ 右主区；主区上 52px 顶栏（`--h-topbar`：页题 / Esc 提示），下为滚动主面板（水平留白 `--pad-x` 24px）。
- **点阵坐标地板**：主面板铺 24px 点阵底纹（`--dot-grid`，次文色 5% 透明度的 1px 圆点），仪表台的地板纹理；内容面板浮于其上。窄窗（≤760px）关闭纹理。
- **密度档**：数据表行高 ≈34px（`td` 上下 7px padding + 13px 基准字号），表头 11px 加 0.06em 字距；面板间距 16px。
- **窄窗降级**：≤760px 侧栏收成 64px 图标轨（`--w-side-narrow`），隐藏导航文字/快捷键/铭牌，内容区关闭点阵纹理。
- **内容宽**：单视图最大 1080px（`--view-max`）。

## Elevation & Depth

纵深主要靠**底色阶差 + 1px 精密线**，阴影只做贴面：

- `--sh-1`（0 1px 2px 黑 40%）：面板贴面，几乎不可感的落地。
- `--sh-2`（0 6px 24px 黑 45%）：仅浮层（toast）保留。
- **凹井**：日志视图、输入井沉到更深的底色（日志 `--s0`、输入 `--s1`），形成"面板上的凹井"。

## Shapes

- **近直角仪表取向**：`--r-1` 3px（kbd）、`--r-2` 5px（按钮/输入框/提示框）、`--r-3` 8px（面板大卡）、`--r-full` 仅用于胶囊徽标与圆形 LED。
- **圆形声呐 LED**：状态灯、白名单条目前点全部是圆形小点——声呐定位语汇，是本体系的识别签名（区别于方形 LED 体系）。

## Components

组件层全部在 `css/app.css`，选择器契约与 `index.html` / `js/**.js` 严格对齐（CSP 禁内联样式，动态状态全部走 class/data 属性）。

- **面板（panel）**：`--s2` 底 + `--ln-1` 边 + 8px 圆角 + 贴面阴影；面板头 `.panel-title` 前置 **14×2px 青色刻度记号**（本体系签名元素，测距语言）。
- **数据行三件套（r1 视觉契约）**：
  - **斑马纹**：`table.data` 偶数行铺 `--zebra`（比面板底沉半档）；表头行不参与。
  - **悬停高亮**：行悬停抬到 `--s3` 交互井，且首格点亮 2px 暗青内轨（`inset 2px 0 0 var(--acc-lo)`，box-shadow 即时切换）。
  - **清晰焦点环**：全局 `:focus-visible` 为 2px 品牌青外圈（offset 2px；按钮上内缩为 1px 防裁切）。
- **状态徽标（chip）**：胶囊描边态 + 圆点 LED，按 `data-s` 契约着色——`created` 待命灰、`running` 亮青字 + LED 呼吸（唯一带动画的状态，`breathe` 1.6s 仅 opacity）、`done` 磷光绿、`fail` 故障红、`stopped` 信号橙；设置页旗标走 `chip-lv-ok/-bad/-warn`。
- **按钮**：主按钮青底墨字、次按钮石板井、停止按钮故障红描边；按压反馈为 1px `translateY` 位移（transform 通道），悬停即时换色不补间。
- **LED（dot）**：8px 圆点，后端状态三态（online 绿 / offline 红 / checking 橙）复用同族。
- **toast**：`--s3` 井底 + `--sh-2`，进场 `toast-in` 0.18s（opacity+translateY）。

## Do's and Don'ts

**Do：**

- 新颜色一律先进 `tokens.css`，组件层只写 `var()`。
- 新状态色必须同时给出 `-lo` 描边档与 `-bg` 淡底档。
- ID/计数/耗时/时间戳一律 `tabular-nums` 等宽排版。
- 交互行必须三者齐备：斑马纹 / 悬停高亮+内轨 / 2px 青色焦点环。
- 动效只用 `opacity` / `transform`；尊重 `prefers-reduced-motion`。
- 图标只用 `index.html` 内手写线条风 SVG，保持 1.6–1.8 描边。

**Don't：**

- 禁止外链：无网络字体、无 CDN、无 `url()` 资源引用。
- 禁止裸色值进 `app.css`。
- 禁止给青鹤安排状态语义（它是唯一品牌强调色，不是状态色）。
- 禁止档外字号、档外间距、方形状态灯。
- 禁止对颜色/边框/填充做 transition 补间。
- 禁止引用任何同类扫描器/终端产品的具体样式值。

## 无障碍

以下数值全部经本会话 WCAG 相对亮度实算（`contrast_check.py`）：

- 主文 `--tx-1 #dee6ec` 对画布 `--s0` ≈ 15.0:1，对面板 `--s2` ≈ 13.2:1。
- 次文 `--tx-2 #9aabb9` 对 `--s0`–`--s3` ≈ 6.4–8.0:1。
- 弱注 `--tx-3 #7a90a4` 对 `--s0`–`--s3` ≈ 4.6–5.7:1，全档过 AA（旧值 `#71879a` 对面板 4.48:1 不达标，r1 提亮修正）。
- 品牌青 `#3cb8a8` 对面板 ≈ 6.8:1；亮青 `#74d6c7` 对面板 ≈ 9.7:1；主按钮墨字 `--acc-ink #04201b` 对青底 ≈ 7.0:1。
- 状态字对面板：绿 ≈ 7.3:1、橙 ≈ 7.4:1、红 ≈ 5.7:1；对各自 `-bg` 淡底全部 ≥5.5:1。
- 表头用 `--tx-2`（7.1:1），不用弱注档。
- `prefers-reduced-motion` 下全部动效压至 0.01ms；键盘焦点环全局 2px 青色。

## 三轮路线图

- **视觉轮 r1（本轮）**：定体系——深色控制室论证、tokens.css 建立（颜色唯一来源 + 状态色三档族 + 字号五档 + 点阵地板 + 斑马纹/行悬停/焦点环契约）、app.css 全量重写（表格密度收紧、等宽数据列、动效收敛到 opacity/transform）、DESIGN.md 按 Google design.md 规范成文。`index.html` / `js/**` 零改动（class 契约不变，tokens.css 由 app.css `@import` 引入）。
- **视觉轮 r2（终稿收口）**：空态精细化、长 URL/长路径折行策略复核、模块进度表耗时列微图表化（纯 CSS）、窄窗（≤760px）与高 DPI 实机复核、对比度全量回归、点阵纹理在低分屏的莫尔纹检查。
