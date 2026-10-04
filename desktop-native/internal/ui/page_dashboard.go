package ui

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/unit"
)

// pageDashboard 仪表盘：统计卡 + 最近任务表 + 白名单提示。
func (a *appUI) pageDashboard(gtx layout.Context) layout.Dimensions {
	tasks := a.tasks
	if tasks == nil {
		tasks = a.sess.Tasks()
	}
	total, running, done, failed := statCounts(tasks)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "仪表盘").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return statCards(gtx, a.th, total, running, done, failed)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "最近任务").Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				rows := TaskRows(tasks)
				n := len(rows)
				if n > 8 {
					n = 8 // 最近 8 条
				}
				if n == 0 {
					return emptyHint(gtx, a.th, "还没有任务——去「新建任务」页发起第一次信息收集")
				}
				return table(gtx, a.th, n,
					[]string{"时间", "目标", "模块", "状态"},
					[]float32{1.2, 2.4, 1, 0.8},
					func(gtx layout.Context, i int) []string {
						return []string{rows[i].CreatedAt, rows[i].Target, rows[i].Module, rows[i].Status}
					})
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "授权目标（白名单红线，名单外一律拒绝）").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(a.th, "xycovo.com   47.100.49.228   127.0.0.1:8799（本机 mock 靶站）", Fs12, ColTx2).Layout(gtx)
								})
							}),
						)
					})
				})
			})
		}),
	)
}

// statCards 四张统计卡：紧凑定宽（180dp）左对齐，不随窗口宽平摊——
// 此前 Flexed(1) 均分 1792px 全宽，卡间距（~342px）远大于卡宽，
// 扫读成本高（真窗口验收 M1）。
func statCards(gtx layout.Context, th *Theme, total, running, done, failed int) layout.Dimensions {
	const cardW = unit.Dp(180)
	cards := []struct {
		name  string
		val   int
		color colorNRGBA
	}{
		{"任务总数", total, ColTx1},
		{"运行中", running, ColAccHi},
		{"已完成", done, ColOk},
		{"失败", failed, ColErr},
	}
	out := make([]layout.FlexChild, 0, 4)
	for _, c := range cards {
		c := c
		out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// 定宽钉在 card 的入参约束上：card 内部 Stack 会清掉内容的
				// Min，钉在内容上无效；card 返回尺寸经 Constrain 抬到 Min，
				// 底色（card 内铺满 Max.X）随之铺满整卡。
				gtx.Constraints.Min.X = gtx.Dp(cardW)
				gtx.Constraints.Max.X = gtx.Constraints.Min.X
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(72))
					return layout.Inset{Top: Sp3, Left: Sp4, Bottom: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return label(th, c.name, Fs11, ColTx2).Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(th, fmt.Sprintf("%d", c.val), Fs15, c.color).Layout(gtx)
								})
							}),
						)
					})
				})
			})
		}))
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, out...)
}

// sectionLabel 区块小标题。
func sectionLabel(th *Theme, s string) labelStyle {
	l := label(th, s, Fs12, ColTx2)
	l.Font.Weight = mediumWeight
	return l
}

// emptyHint 空态提示。
func emptyHint(gtx layout.Context, th *Theme, s string) layout.Dimensions {
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(64))
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return label(th, s, Fs13, ColTx3).Layout(gtx)
		})
	})
}
