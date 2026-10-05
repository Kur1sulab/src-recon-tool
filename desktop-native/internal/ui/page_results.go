package ui

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// pageResults 结果页：模块 tab + 任务列表（分页）+ 选中任务过程表（分页）
// + 证据包导出入口。
func (a *appUI) pageResults(gtx layout.Context) layout.Dimensions {
	filtered := a.listTasks()
	rows := TaskRows(filtered)
	start, end, listPages := PageBounds(len(rows), a.listPage, PageSize)
	pageRows := rows[start:end]

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// 标题行：结果 + 证据包导出
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
					btn.Background = ColErrBg
					btn.Color = ColErr
					btn.CornerRadius = R2
					return btn.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						labelTxt, bg, fg := "导出证据包", ColS3, ColTx1
						if a.exportBusy {
							labelTxt, bg, fg = "正在打包…", ColS1, ColTx3
						}
						btn := material.Button(a.th.Theme, &a.exportBtn, labelTxt)
						btn.Background = bg
						btn.Color = fg
						btn.CornerRadius = R2
						return btn.Layout(gtx)
					})
				}),
			)
		}),
		// 导出回执 / 错误行
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if a.exportMsg == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				col := ColOk
				if len(a.exportMsg) > 3 && a.exportMsg[:4] == "导出失败" {
					col = ColErr
				}
				l := monoLabel(a.th, a.exportMsg, Fs12, col)
				l.MaxLines = 2
				return l.Layout(gtx)
			})
		}),
		// 模块 tab 行
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, a.moduleTabRow)
		}),
		// 任务列表（分页）
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if len(rows) == 0 {
					if len(a.tasks) == 0 {
						return emptyHint(gtx, a.th, "还没有任务记录——到「新建任务」页发起第一次信息收集")
					}
					return emptyHint(gtx, a.th, "该模块还没有任务记录，点上方 tab 切回「全部」看看")
				}
				return a.taskListTable(gtx, pageRows)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if listPages <= 0 {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.pagerRow(gtx, a.listPage, listPages, &a.prevList, &a.nextList)
			})
		}),
		// 选中任务详情 + 过程表（分页）
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, a.taskDetail)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			_, _, rowsPages := PageBounds(a.selectedRowsCount(), a.rowsPage, PageSize)
			if rowsPages <= 1 {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.pagerRow(gtx, a.rowsPage, rowsPages, &a.prevRows, &a.nextRows)
			})
		}),
	)
}

// moduleTabRow 模块 tab：胶囊按钮横排（横向可滚——11 胶囊 × 88dp = 968dp
// 超出主区 908dp 内容宽，固定行会裁掉最后一枚，实测截图钉住），
// 选中 acc-bg/亮青，未选 s2/次文。
func (a *appUI) moduleTabRow(gtx layout.Context) layout.Dimensions {
	tabs := tabKeys()
	chipW := gtx.Dp(unit.Dp(80)) // 11×80=880dp ≤ 主区 908dp：默认全见；超出仍可横向滚
	a.tabList.Axis = layout.Horizontal
	return a.tabList.Layout(gtx, len(tabs), func(gtx layout.Context, i int) layout.Dimensions {
		m := tabs[i]
		c := a.tabClick(m.Key)
		active := a.moduleTab.Value == m.Key
		bg, fg := ColS2, ColTx2
		switch {
		case active:
			bg, fg = ColAccBg, ColAccHi
		case c.Hovered():
			bg, fg = ColS3, ColTx1
		}
		gtx.Constraints.Min.X = chipW
		gtx.Constraints.Max.X = chipW
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(26))
		bl := material.ButtonLayout(a.th.Theme, c)
		bl.Background = bg
		bl.CornerRadius = unit.Dp(999) // 胶囊（r-full）
		return bl.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := label(a.th, m.Label, Fs11, fg)
				if active {
					l.Font.Weight = mediumWeight
				}
				return l.Layout(gtx)
			})
		})
	})
}

// pagerRow 分页条：‹ 上一页 / 第 x / y 页 / 下一页 ›。
func (a *appUI) pagerRow(gtx layout.Context, page, pages int, prev, next *widget.Clickable) layout.Dimensions {
	btn := func(c *widget.Clickable, txt string, enabled bool) layout.FlexChild {
		return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			bg, fg := ColS3, ColTx1
			if !enabled {
				bg, fg = ColS1, ColTx3
			}
			gtx.Constraints.Min.X = gtx.Dp(unit.Dp(84))
			gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(26))
			bl := material.ButtonLayout(a.th.Theme, c)
			bl.Background = bg
			bl.CornerRadius = R2
			return bl.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return label(a.th, txt, Fs11, fg).Layout(gtx)
				})
			})
		})
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		btn(prev, "‹ 上一页", page > 1),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: Sp3, Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return monoLabel(a.th, fmt.Sprintf("第 %d / %d 页", page, pages), Fs11, ColTx2).Layout(gtx)
			})
		}),
		btn(next, "下一页 ›", page < pages),
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
			list := a.taskList // 持久 List：滚动位置跨帧存活
			list.Axis = layout.Vertical
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
		a.rowsPage = 1 // 换任务回过程表第一页
	}
	return c
}

// taskDetail 选中任务概要 + 过程表（分页）。
func (a *appUI) taskDetail(gtx layout.Context) layout.Dimensions {
	if a.selID == "" {
		return emptyHint(gtx, a.th, "在上方列表点一行查看过程")
	}
	t, ok := a.sess.Task(a.selID)
	if !ok {
		return emptyHint(gtx, a.th, "任务已被清理")
	}
	rows := ResultRows(t)
	// 基线任务：过程事件行之后追加「每检查结论」行（每个检查在结果表都有
	// 对应行——结论逐检查一行，未运行/失败态照实标注，不编造）。
	if t.Cmd == "baseline" && a.selBaseStates != nil {
		rows = append(rows, BaselineConclusionRows(a.selBaseStates)...)
	}
	start, end, _ := PageBounds(len(rows), a.rowsPage, PageSize)
	pageRows := rows[start:end]

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
					return emptyHint(gtx, a.th, "暂无过程记录（任务刚提交时这里会是空的，跑起来就有）")
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "过程记录").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(a.th, fmt.Sprintf("共 %d 条", len(rows)), Fs11, ColTx3).Layout(gtx)
								})
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							return resultTable(gtx, a.th, pageRows, &a.procList)
						})
					}),
				)
			})
		}),
	)
}

// resultTable 过程记录表（斑马纹，List 虚拟化；lst 持久化滚动位置）。
func resultTable(gtx layout.Context, th *Theme, rows []ResultRow, lst *layout.List) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return tableRow(gtx, th, []string{"时间", "模块", "事件", "详情"}, []float32{0.7, 0.9, 1, 3}, true)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return hairline(gtx, ColLn1)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(300))
			lst.Axis = layout.Vertical
			return lst.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
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
