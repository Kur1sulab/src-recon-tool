package ui

import (
	"fmt"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"unicode/utf8"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/io/event"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ── 「浅色工程台 Light Bench」色板（用户裁定 2026-10-05 改浅色）──
// 逐值转译自 design-proposals/C-tokens.css 的 [data-theme="light"] 覆盖块
// （31 令牌，34 组 WCAG 硬门槛配对实测全过，见 C-dual-theme.md §9）。
// 层级方向与深色相反：面板最亮（纸面白），骨架/画布/井位反向压灰；
// 强调色取深青档保文字对比（主按钮悬停由变亮反转为加深）。
// 硬边界（实测红线，两主题同口径）：
//
//	· Tx3 弱注禁上 S4 强井；
//	· Idle 待命灰只作 LED / 描边，禁作文字色。
var (
	// 工程台五级底（纸面反转：面板最亮，井位压灰）
	ColS0 = nrgba(0xeef1f4) // 画布：应用最底 / 日志凹井（比面板沉半档）
	ColS1 = nrgba(0xe5eaef) // 骨架：侧栏 / 顶栏 / 输入井
	ColS2 = nrgba(0xffffff) // 面板：卡片标准底（纸面白，最亮层）
	ColS3 = nrgba(0xe4eaef) // 交互井：行悬停 / 下拉悬停
	ColS4 = nrgba(0xd7dfe6) // 强井：按钮悬停 / 选中井

	// 精密边框三阶（浅色下线条略实才可见）
	ColLn1 = nrgba(0xdde4ea) // 行分隔 / 面板内发丝线
	ColLn2 = nrgba(0xc7d2db) // 面板边 / 控件默认边
	ColLn3 = nrgba(0xa9bac6) // 悬停边 / 强调边

	// 文字三阶（冷蓝墨，对 s0–s3 全部 ≥4.5:1 实测）
	ColTx1 = nrgba(0x1c2833) // 主文：正文 / 数据值（对面板 14.99:1）
	ColTx2 = nrgba(0x46596a) // 次文：标签 / 表头 / 提示
	ColTx3 = nrgba(0x52687a) // 弱注：脚注（不上 s4，实测 4.31 红线不变）

	// 品牌青鹤（唯一强调色，浅色取深青档保文字对比）
	ColAcc    = nrgba(0x0d7668) // 深青：焦点环 / 激活轨 / 主按钮底（对面板 5.51:1）
	ColAccHi  = nrgba(0x0a6357) // 强青：悬停加深档 / 运行态字（对面板 7.15:1）
	ColAccLo  = nrgba(0x3e9488) // 中青：描边档（对面板 3.62:1）
	ColAccInk = nrgba(0xffffff) // 青上字：主按钮文字（对青底 5.51:1）
	ColAccBg  = nrgba(0xd9efeb) // 青淡底：选中井（主文对它 12.49:1）

	// 状态色族（绿=完成 橙=警示 红=故障 灰=待命；同一色相族的浅色文字档）
	ColOk     = nrgba(0x17722f)
	ColOkLo   = nrgba(0x85c396)
	ColOkBg   = nrgba(0xeaf6ee)
	ColWarn   = nrgba(0x8f5e00)
	ColWarnLo = nrgba(0xd9b45c)
	ColWarnBg = nrgba(0xfaf3df)
	ColErr    = nrgba(0xc0362e)
	ColErrLo  = nrgba(0xe6a49d)
	ColErrBg  = nrgba(0xfdecea)
	ColIdle   = nrgba(0x5b6f82) // 两主题同值：LED 对白面板 5.20:1，禁作文字色
	ColIdleBg = nrgba(0xe3e9ee)

	ColZebra = nrgba(0xf4f7f9) // 斑马纹：比白面板沉半档
)

// nrgba 0xRRGGBB → color.NRGBA（不透明）。
func nrgba(v int) color.NRGBA {
	return color.NRGBA{
		R: uint8(v >> 16 & 0xff),
		G: uint8(v >> 8 & 0xff),
		B: uint8(v & 0xff),
		A: 0xff,
	}
}

// colorNRGBA 包内简写别名。
type colorNRGBA = color.NRGBA

// paintFill 当前裁剪区填色。
func paintFill(gtx layout.Context, c colorNRGBA) {
	paint.Fill(gtx.Ops, c)
}

// clipRect 压入矩形裁剪并返回弹出函数（配合 defer；size 为 Point 形矩形）。
func clipRect(gtx layout.Context, size image.Point) func() {
	return clip.Rect{Max: size}.Push(gtx.Ops).Pop
}

// clipCircle 压入直径 d 的圆形裁剪并返回弹出函数（LED 状态点用）。
func clipCircle(gtx layout.Context, d int) func() {
	return clip.UniformRRect(image.Rectangle{Max: image.Pt(d, d)}, d/2).Push(gtx.Ops).Pop
}

// 包内简写别名。
type labelStyle = material.LabelStyle

const mediumWeight = font.Medium

// ── 字号五档（档外禁用，px→sp 同值转译）──
const (
	Fs11 = unit.Sp(11) // 表头 / kbd / 铭牌
	Fs12 = unit.Sp(12) // 徽标 / 脚注 / 日志 / 表格数据
	Fs13 = unit.Sp(13) // 正文（基准）
	Fs14 = unit.Sp(14) // 输入框
	Fs15 = unit.Sp(15) // 页题 / 品牌名
)

// ── 间距（4 的倍数，dp）──
const (
	Sp1 = unit.Dp(4)
	Sp2 = unit.Dp(8)
	Sp3 = unit.Dp(12)
	Sp4 = unit.Dp(16)
	Sp5 = unit.Dp(20)
	Sp6 = unit.Dp(24)
)

// ── 圆角（近直角仪表取向；8 不嵌 8）──
const (
	R1 = unit.Dp(3) // 小徽标
	R2 = unit.Dp(5) // 按钮 / 输入井
	R3 = unit.Dp(8) // 面板大卡
)

// 布局尺寸。
const (
	SideW  = unit.Dp(224) // 侧栏宽
	TopH   = unit.Dp(52)  // 顶栏高
	PadX   = unit.Dp(24)  // 主区水平留白
	RowH   = unit.Dp(30)  // 表格行高（紧凑密度）
	MonoTF = "Consolas"   // 等宽阶梯：数据列字体名（缺失时回退默认）
)

// loadFaces 优先系统微软雅黑（中文渲染）+ Consolas（等宽数据列），
// 任一失败回退 Gio 内置字体（无中文字形，交付精简系统会出豆腐块——
// 内嵌兜底字体待 assets 立项，见交付说明）。
func loadFaces() (faces []font.FontFace, hasMono bool) {
	faces = gofont.Collection()
	// 中文主字体逐级回退：msyh.ttc 缺失不再单点出豆腐块——
	// msyhl.ttc（雅黑 Light）/ simsun.ttc（宋体）Windows 全系自带
	cjkLoaded := false
	for _, name := range []string{"msyh.ttc", "msyhl.ttc", "simsun.ttc"} {
		b, err := os.ReadFile(filepath.Join(`C:\Windows\Fonts`, name))
		if err != nil {
			continue
		}
		fs, err := opentype.ParseCollection(b)
		if err != nil {
			continue
		}
		faces, cjkLoaded = fs, true
		break
	}
	if !cjkLoaded {
		// 三级全空（精简/裁剪系统）：写一行到 stderr 便于交付排查
		fmt.Fprintln(os.Stderr, "信息收集工具：未找到系统中文字体（msyh.ttc/msyhl.ttc/simsun.ttc），界面中文将显示为方块")
	}
	if b, err := os.ReadFile(`C:\Windows\Fonts\consola.ttf`); err == nil {
		if fs, err := opentype.ParseCollection(b); err == nil {
			faces = append(faces, fs...)
			hasMono = true
		}
	}
	return faces, hasMono
}

// Theme 浅色工程台主题：material 主题 + 等宽字体可用性。
type Theme struct {
	*material.Theme
	HasMono bool
}

// NewTheme 构建浅色主题：雅黑注册、工程台色板、13sp 正文基准。
func NewTheme() *Theme {
	faces, hasMono := loadFaces()
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(faces))
	th.TextSize = Fs13
	th.Palette = material.Palette{
		Fg:         ColTx1,
		Bg:         ColS2,
		ContrastBg: ColAcc,    // 主按钮底 = 品牌青
		ContrastFg: ColAccInk, // 主按钮文字 = 青上墨
	}
	return &Theme{Theme: th, HasMono: hasMono}
}

// ── 绘制小件 ──

// fillRect 以给定颜色铺满当前约束区。
func fillRect(gtx layout.Context, c color.NRGBA) layout.Dimensions {
	size := gtx.Constraints.Min
	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, c)
	return layout.Dimensions{Size: size}
}

// card 圆角面板底（r3 大卡 / r2 输入井）。宽度铺满当前约束（定宽槽或
// 全宽由调用方约束决定），高度跟内容自然高。底色宽度必须自己钉到
// Max.X：Stack 会把 Stacked 内容的 Min 清零、把 Expanded 的 Min 只抬到
// 内容自然尺寸（gioui.org@v0.10.3 layout/stack.go:53,74），按 Min 铺色
// 会漏出「文字有多宽、底就有多宽」的次生缺口（真窗口验收复现）。
func card(gtx layout.Context, bg colorNRGBA, radius unit.Dp, w layout.Widget) layout.Dimensions {
	return layout.Stack{Alignment: layout.NW}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, gtx.Dp(radius)).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(w),
	)
}

// cardFill 满分配区圆角面板：底色吃满当前 Flex 槽位的全部空间。
// 只用于区域容器（侧栏 / 主区 / 顶栏这类"该区域整体一个底色"的地方）；
// 内容型面板（统计卡 / 提示条）仍用 card，高度跟内容走。
// 为什么铺不满：Gio Stack 的 Expanded 子件只把 Constraints.Min 抬到
// Stacked 子件的自然尺寸（gioui.org@v0.10.3 layout/stack.go:74），底色若
// 按 Min 铺就只有内容那么高——所以铺满必须由底色 widget 自己把 Min
// 钉到 Max。此即真窗口验收「客户区大片纯白 / 顶栏被剥开」的根因。
func cardFill(gtx layout.Context, bg colorNRGBA, radius unit.Dp, w layout.Widget) layout.Dimensions {
	gtx.Constraints.Min = gtx.Constraints.Max
	return layout.Stack{Alignment: layout.NW}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min = gtx.Constraints.Max
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, gtx.Dp(radius)).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(w),
	)
}

// focusRing 2dp 品牌青焦点环（描边不填色，不影响布局； Gio material
// 控件不自带焦点可视，验收「Tab 焦点不可辨」的修复件）。
func focusRing(gtx layout.Context, size image.Point, radius unit.Dp) {
	p := clip.UniformRRect(image.Rectangle{Max: size}, gtx.Dp(radius))
	st := clip.Stroke{Path: p.Path(gtx.Ops), Width: float32(gtx.Dp(unit.Dp(2)))}
	defer st.Op().Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, ColAcc)
}

// focusOutline 焦点落在此控件（Gio key tag，通常为 *widget.Clickable /
// *widget.Editor）时沿已布局区域补描焦点环。Gio material 按钮/折叠钮
// 不自带焦点可视，Tab 遍历一圈焦点位置不可辨（验收 B4「焦点位置肉眼
// 可辨」）；与输入井同款口径（page_newtask.go inputWell）。
// dims 原样返回，不影响布局。
func focusOutline(gtx layout.Context, key event.Tag, dims layout.Dimensions, radius unit.Dp) layout.Dimensions {
	if gtx.Focused(key) {
		focusRing(gtx, dims.Size, radius)
	}
	return dims
}

// hairline 1dp 发丝线（行分隔 / 面板内线）。
func hairline(gtx layout.Context, c color.NRGBA) layout.Dimensions {
	h := gtx.Dp(unit.Dp(1))
	size := image.Pt(gtx.Constraints.Min.X, h)
	defer clip.Rect{Max: size}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, c)
	return layout.Dimensions{Size: size}
}

// label 主文标签。
func label(th *Theme, s string, size unit.Sp, col color.NRGBA) material.LabelStyle {
	l := material.Body1(th.Theme, s)
	l.TextSize = size
	l.Color = col
	return l
}

// isASCII 字符串是否纯 ASCII。Consolas 无中文字形，混排中文走等宽
// 字体会逐字缺字留空（真窗口验收的「白名　内才　」丢字），必须回退。
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// monoLabel 等宽数据标签：纯 ASCII 才上 Consolas（DESIGN.md 纪律：
// 等宽只用于 ASCII 数据列）；含中文/全角标点回退默认字体（雅黑）。
func monoLabel(th *Theme, s string, size unit.Sp, col colorNRGBA) material.LabelStyle {
	l := label(th, s, size, col)
	if th.HasMono && isASCII(s) {
		l.Font.Typeface = MonoTF
	}
	return l
}

// titleLabel 页题 / 品牌名（15sp 半粗）。
func titleLabel(th *Theme, s string) material.LabelStyle {
	l := label(th, s, Fs15, ColTx1)
	l.Font.Weight = font.SemiBold
	return l
}

// statusColor 状态 → 语义色（文字档；idle 不作文字色故用 Tx2 表达待命）。
func statusColor(status string) color.NRGBA {
	switch status {
	case "running":
		return ColAccHi
	case "done":
		return ColOk
	case "fail":
		return ColErr
	}
	return ColTx2 // created / stopped / 未知：待命用次文灰表达
}
