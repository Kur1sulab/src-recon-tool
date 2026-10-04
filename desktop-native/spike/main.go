// Gio 构建尖峰：最小窗口 = 一个按钮 + 一张三行表格（表头+3行数据）。
// 验证目标：gioui.org v0.10.3 在 Windows 纯 Go（零 CGO）下 build 出 exe 且能起窗口。
// 附带验证中文渲染：注册微软雅黑 msyh.ttc（TTC）作为 UI 字体。
package main

import (
	"fmt"
	"os"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

type ui struct {
	btn    widget.Clickable
	clicks int
	rows   [][3]string // 三行表格数据：域名 / 主机 / 状态
}

// loadFaces 优先加载系统微软雅黑（中文渲染），失败回退 Gio 内置字体。
func loadFaces() []font.FontFace {
	b, err := os.ReadFile(`C:\Windows\Fonts\msyh.ttc`)
	if err != nil {
		fmt.Println("FONT: read msyh.ttc fail:", err)
		return gofont.Collection()
	}
	faces, err := opentype.ParseCollection(b)
	if err != nil {
		fmt.Println("FONT: parse msyh.ttc fail:", err)
		return gofont.Collection()
	}
	fmt.Println("FONT: msyh.ttc ok, faces =", len(faces))
	return faces
}

func main() {
	go func() {
		w := new(app.Window)
		w.Option(app.Title("信息收集工具 · Gio 构建尖峰"), app.Size(640, 420))
		if err := run(w); err != nil {
			fmt.Println("ERR:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
	app.Main()
}

func run(w *app.Window) error {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(loadFaces()))

	u := &ui{rows: [][3]string{
		{"example.com", "www.example.com", "200"},
		{"test.org", "api.test.org", "404"},
		{"demo.cn", "mail.demo.cn", "200"},
	}}

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			fmt.Println("WIN: destroyed")
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if u.btn.Clicked(gtx) {
				u.clicks++
				fmt.Println("BTN: clicked", u.clicks)
			}
			drawUI(gtx, th, u)
			e.Frame(gtx.Ops)
		}
	}
}

func drawUI(gtx layout.Context, th *material.Theme, u *ui) layout.Dimensions {
	inset := layout.UniformInset(12)
	return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// 按钮行
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := "测试按钮"
				if u.clicks > 0 {
					label = fmt.Sprintf("测试按钮（点了 %d 次）", u.clicks)
				}
				return material.Button(th, &u.btn, label).Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
			// 表格：表头 + 三行数据，三列网格
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				rows := make([][3]string, 0, len(u.rows)+1)
				rows = append(rows, [3]string{"域名", "主机", "状态"})
				rows = append(rows, u.rows...)
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					list := layout.List{Axis: layout.Vertical}
					return list.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
						return drawRow(gtx, th, rows[i], i == 0)
					})
				})
			}),
		)
	})
}

func drawRow(gtx layout.Context, th *material.Theme, row [3]string, header bool) layout.Dimensions {
	weights := []float32{1, 1.4, 0.6}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawCell(gtx, th, row[0], weights[0], header)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawCell(gtx, th, row[1], weights[1], header)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return drawCell(gtx, th, row[2], weights[2], header)
		}),
	)
}

func drawCell(gtx layout.Context, th *material.Theme, text string, weight float32, header bool) layout.Dimensions {
	l := material.Body1(th, text)
	if header {
		l.TextSize = unit.Sp(14)
		l.Color = th.Palette.ContrastBg
	}
	gtx.Constraints.Min.X = gtx.Dp(unit.Dp(170 * weight))
	return l.Layout(gtx)
}
