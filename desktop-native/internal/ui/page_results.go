package ui

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// pageResults 结果页：任务列表（可选中）+ 选中任务的过程表格。
func (a *appUI) pageResults(gtx layout.Context) layout.Dimensions {
	rows := TaskRows(a.tasks)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return titleLabel(a.th, "结果").Layout(gtx)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if a.selID == "" {
						return layout.Dimensions{}
					}
					t, ok := a.sess.Task(a.selID)
					if !ok || (t.Status != "running" && t.Status != "created") {
						return layout.Dimensions{}
					}
					btn := material.Button(a.th.Theme, &a.stopBtn, "停止选中任务")
					btn.Background = ColErrLo
					btn.Color = ColTx1
					return btn.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if len(rows) == 0 {
					return emptyHint(gtx, a.th, "还没有任务记录")
				}
				// 任务列表固定高度（10 行左右），避免把过程表挤没
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(11 * 30))
						return a.taskListTable(gtx, rows)
					}),
				)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, a.taskDetail)
		}),
	)
}

// taskListTable 任务列表表格：整行可点击选中。
func (a *appUI) taskListTable(gtx layout.Context, rows []TaskRow) layout.Dimensions {
	headers := []string{"时间", "目标", "模块", "状态", ""}
	widths := []float32{1.2, 2.4, 1, 0.8, 0.5}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return tableRow(gtx, a.th, headers, widths, true)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return hairline(gtx, ColLn1)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			list := layout.List{Axis: layout.Vertical}
			return list.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
				r := rows[i]
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				body := []string{r.CreatedAt, r.Target, r.Module, r.Status, selectedMark(a.selID == r.ID)}
				c := a.taskClick(r.ID, gtx)
				selected := a.selID == r.ID
				return layout.Stack{Alignment: layout.W}.Layout(gtx,
					layout.Expanded(func(gtx layout.Context) layout.Dimensions {
						bg := colorNRGBA{}
						switch {
						case selected:
							bg = ColS4
						case i%2 == 1:
							bg = ColZebra
						case c.Hovered():
							bg = ColS3
						}
						if bg.A == 0 {
							return layout.Dimensions{Size: gtx.Constraints.Min}
						}
						return fillRect(gtx, bg)
					}),
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						bl := material.ButtonLayout(a.th.Theme, c)
						bl.Background = colorNRGBA{A: 0}
						bl.CornerRadius = 0
						return bl.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return tableRow(gtx, a.th, body, widths, false)
						})
					}),
				)
			})
		}),
	)
}

// selectedMark 选中标记列。
func selectedMark(sel bool) string {
	if sel {
		return "▶ 选中"
	}
	return ""
}

// taskClick 返回任务行自己的 Clickable；有则处理本帧点击（每帧恰一次）。
func (a *appUI) taskClick(id string, gtx layout.Context) *widget.Clickable {
	c, ok := a.taskClicks[id]
	if !ok {
		c = &widget.Clickable{}
		a.taskClicks[id] = c
	}
	if c.Clicked(gtx) {
		a.selID = id
	}
	return c
}

// taskDetail 选中任务的过程表格。
func (a *appUI) taskDetail(gtx layout.Context) layout.Dimensions {
	if a.selID == "" {
		return emptyHint(gtx, a.th, "在上方列表点一行查看过程")
	}
	t, ok := a.sess.Task(a.selID)
	if !ok {
		return emptyHint(gtx, a.th, "任务已被清理")
	}
	rows := ResultRows(t)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// 概要卡
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return sectionLabel(a.th, "任务 "+t.ID).Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return label(a.th, StatusText(t.Status), Fs12, statusColor(t.Status)).Layout(gtx)
									})
								}),
							)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								exit := ""
								if t.ExitCode != nil {
									exit = fmt.Sprintf("，退出码 %d", *t.ExitCode)
								}
								return monoLabel(a.th,
									fmt.Sprintf("目标 %s ｜ 模块 %s ｜ 开始 %s ｜ 结束 %s%s",
										t.Target, moduleLabel(t.Cmd), fmtSeconds(t.CreatedAt), fmtSeconds(t.FinishedAt), exit),
									Fs12, ColTx2).Layout(gtx)
							})
						}),
					)
				})
			})
		}),
		// 过程表
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if len(rows) == 0 {
					return emptyHint(gtx, a.th, "暂无过程记录")
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return sectionLabel(a.th, "过程记录（最新在底部）").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return resultTable(gtx, a.th, rows)
						})
					}),
				)
			})
		}),
	)
}

// resultTable 过程记录表（List 虚拟化，上万行也不虚）。
func resultTable(gtx layout.Context, th *Theme, rows []ResultRow) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return tableRow(gtx, th, []string{"时间", "模块", "事件", "详情"}, []float32{0.7, 0.9, 1, 3}, true)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return hairline(gtx, ColLn1)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(360))
			list := layout.List{Axis: layout.Vertical}
			return list.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				r := rows[i]
				body := []string{r.Time, r.Module, r.Event, r.Detail}
				if i%2 == 1 {
					return layout.Stack{Alignment: layout.W}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							return fillRect(gtx, ColZebra)
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return tableRow(gtx, th, body, []float32{0.7, 0.9, 1, 3}, false)
						}),
					)
				}
				return tableRow(gtx, th, body, []float32{0.7, 0.9, 1, 3}, false)
			})
		}),
	)
}
