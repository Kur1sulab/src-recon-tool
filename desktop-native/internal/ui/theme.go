package ui

import (
	"image"
	"image/color"
	"os"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// ── 「石板声呐 Slate Sonar」色板 ──
// 逐值转译自 frontend/css/tokens.css（唯一颜色来源，深色为唯一规范主题）。
// 硬边界（WCAG 实测红线，与 tokens.css 注释一致）：
//
//	· Tx3 禁上 S4（4.06:1）——S4 井底文字至少 Tx2；
//	· Idle 禁放 S3 井底（2.92:1，非文字 3:1 门槛）；
//	· Idle 不作文字色（对 S2 仅 3.21:1）；
//	· -lo 描边档只描边，禁作文字色。
var (
	// 石板五级底（冷蓝相，纵深全靠阶差）
	ColS0 = nrgba(0x0c1116) // 画布：应用最底 / 日志凹井
	ColS1 = nrgba(0x101820) // 骨架：侧栏 / 顶栏 / 输入井
	ColS2 = nrgba(0x151f28) // 面板：卡片标准底
	ColS3 = nrgba(0x1b2732) // 交互井：行悬停 / 下拉悬停
	ColS4 = nrgba(0x223040) // 强井：按钮悬停 / 选中井（文字至少 Tx2）

	// 精密边框三阶（全部 1px 发丝线）
	ColLn1 = nrgba(0x1e2b36) // 行分隔 / 面板内发丝线
	ColLn2 = nrgba(0x273745) // 面板边 / 控件默认边
	ColLn3 = nrgba(0x354857) // 悬停边 / 强调边 / idle 族成文例外边线

	// 文字三阶（冷蓝灰）
	ColTx1 = nrgba(0xdee6ec) // 主文：正文 / 数据值
	ColTx2 = nrgba(0x9aabb9) // 次文：标签 / 表头 / 提示
	ColTx3 = nrgba(0x7a90a4) // 弱注：脚注（对 s0–s3 过 AA；禁上 s4）

	// 品牌青鹤（唯一强调色，绝不参与状态语义）
	ColAcc    = nrgba(0x3cb8a8) // 焦点环 / 激活轨 / 主按钮底
	ColAccHi  = nrgba(0x74d6c7) // 亮青：青底上的悬停 / 运行态字
	ColAccLo  = nrgba(0x1d4a43) // 暗青：描边档
	ColAccInk = nrgba(0x04201b) // 青上墨：主按钮文字
	ColAccBg  = nrgba(0x102e2b) // 青淡底：选中井

	// 状态色族（绿=完成 橙=警示 红=故障 灰=待命）
	ColOk     = nrgba(0x63bd80)
	ColOkLo   = nrgba(0x2a5c3c)
	ColOkBg   = nrgba(0x15271d)
	ColWarn   = nrgba(0xd9a353)
	ColWarnLo = nrgba(0x6b5426)
	ColWarnBg = nrgba(0x2a2216)
	ColErr    = nrgba(0xe07b6c)
	ColErrLo  = nrgba(0x6e3a33)
	ColErrBg  = nrgba(0x2c1d1a)
	ColIdle   = nrgba(0x5b6f82) // 只作 LED / 描边，禁作文字色
	ColIdleBg = nrgba(0x131c24)

	ColZebra = nrgba(0x121b23) // 斑马纹：比面板底沉半档
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
	if b, err := os.ReadFile(`C:\Windows\Fonts\msyh.ttc`); err == nil {
		if fs, err := opentype.ParseCollection(b); err == nil {
			faces = fs
		}
	}
	if b, err := os.ReadFile(`C:\Windows\Fonts\consola.ttf`); err == nil {
		if fs, err := opentype.ParseCollection(b); err == nil {
			faces = append(faces, fs...)
			hasMono = true
		}
	}
	return faces, hasMono
}

// Theme 石板声呐主题：material 主题 + 等宽字体可用性。
type Theme struct {
	*material.Theme
	HasMono bool
}

// NewTheme 构建深色主题：雅黑注册、石板色板、13sp 正文基准。
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

// card 圆角面板底（r3 大卡 / r2 输入井），内容居上铺满。
func card(gtx layout.Context, bg color.NRGBA, radius unit.Dp, w layout.Widget) layout.Dimensions {
	return layout.Stack{Alignment: layout.NW}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, gtx.Dp(radius)).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, bg)
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(w),
	)
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

// monoLabel 等宽数据标签（仅用于 ASCII 数据列；字体缺失回退默认）。
func monoLabel(th *Theme, s string, size unit.Sp, col color.NRGBA) material.LabelStyle {
	l := label(th, s, size, col)
	if th.HasMono {
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
