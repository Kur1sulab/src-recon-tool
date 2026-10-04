package ui

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// pageNewTask 新建任务：目标 → 模块 → 可选参数 → 开始。
func (a *appUI) pageNewTask(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "新建任务").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp4, Right: Sp4, Bottom: Sp4, Left: Sp4}.Layout(gtx, a.newTaskForm)
				})
			})
		}),
	)
}

// argHint 按所选模块给出可选参数提示（与 engine.moduleFlags 一致）。
func argHint(module string) string {
	switch module {
	case "portscan":
		return "可选：--ports 1-1000  --timeout 3  --workers 50"
	case "jsintel":
		return "可选：--max-files 20  --workers 4"
	case "subdomain":
		return "可选：--verify（对枚举结果做存活验证）"
	default:
		return "该模块没有可选参数，留空即可"
	}
}

func (a *appUI) newTaskForm(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// 目标
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return sectionLabel(a.th, "扫描目标").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return inputWell(gtx, a.th, &a.targetEd, Fs14, "输入目标：域名 / IP / URL")
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return monoLabel(a.th, "白名单内才允许：xycovo.com / 47.100.49.228 / http://127.0.0.1:8799/real", Fs11, ColTx3).Layout(gtx)
			})
		}),
		// 模块
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "选择模块").Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, moduleGrid(a))
		}),
		// 可选参数
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "可选参数（最多 8 段，禁止夹带目标）").Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return inputWell(gtx, a.th, &a.argsEd, Fs14, "例如：--ports 1-1000")
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return monoLabel(a.th, argHint(a.moduleSel.Value), Fs11, ColTx3).Layout(gtx)
			})
		}),
		// 开始
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(a.th.Theme, &a.startBtn, "开始扫描")
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(btn.Layout),
				)
			})
		}),
		// 错误 / 成功提示
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.newErr == "" && a.newOK == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if a.newErr != "" {
					return errBanner(gtx, a.th, a.newErr)
				}
				return okBanner(gtx, a.th, a.newOK)
			})
		}),
	)
}

// moduleGrid 九个模块按三列一组排布（单选）。
func moduleGrid(a *appUI) layout.Widget {
	rows := (len(Modules) + 2) / 3
	return func(gtx layout.Context) layout.Dimensions {
		out := make([]layout.FlexChild, 0, rows)
		for r := 0; r < rows; r++ {
			r := r
			out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				cells := make([]layout.FlexChild, 0, 3)
				for c := 0; c < 3; c++ {
					idx := r*3 + c
					if idx >= len(Modules) {
						break
					}
					m := Modules[idx]
					cells = append(cells, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						rb := material.RadioButton(a.th.Theme, &a.moduleSel, m.Key, m.Label)
						rb.Color = ColTx1
						return layout.Inset{Top: Sp1, Bottom: Sp1}.Layout(gtx, rb.Layout)
					}))
				}
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, cells...)
			}))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
	}
}

// inputWell 输入井：s1 底 + r2 圆角 + 内嵌编辑器。
func inputWell(gtx layout.Context, th *Theme, ed *widget.Editor, size unit.Sp, hint string) layout.Dimensions {
	return card(gtx, ColS1, R2, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(40))
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: unit.Dp(9), Bottom: unit.Dp(9), Left: Sp3, Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			e := material.Editor(th.Theme, ed, hint)
			e.TextSize = size
			e.Color = ColTx1
			e.HintColor = ColTx3
			return e.Layout(gtx)
		})
	})
}

// errBanner 错误横条（err-bg 底 + err 字）。
func errBanner(gtx layout.Context, th *Theme, s string) layout.Dimensions {
	return banner(gtx, th, s, ColErrBg, ColErr)
}

// okBanner 成功横条（ok-bg 底 + ok 字）。
func okBanner(gtx layout.Context, th *Theme, s string) layout.Dimensions {
	return banner(gtx, th, s, ColOkBg, ColOk)
}

func banner(gtx layout.Context, th *Theme, s string, bg, fg colorNRGBA) layout.Dimensions {
	return card(gtx, bg, R2, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp2, Bottom: Sp2, Left: Sp3, Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			l := label(th, s, Fs12, fg)
			l.MaxLines = 3
			return l.Layout(gtx)
		})
	})
}
