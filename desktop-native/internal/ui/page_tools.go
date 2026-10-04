package ui

import (
	"fmt"
	"path/filepath"

	"gioui.org/layout"
	"gioui.org/widget/material"
)

// pageTools 工具页：模块说明 + mock 靶站探测 + 产物目录。
func (a *appUI) pageTools(gtx layout.Context) layout.Dimensions {
	_, _, _, _, mock, _, mockPro := a.env.snapshot()

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "工具").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "扫描模块（九个，全部本地出数）").Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				out := make([]layout.FlexChild, 0, len(Modules))
				for _, m := range Modules {
					m := m
					out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									l := label(a.th, m.Label, Fs13, ColTx1)
									l.MaxLines = 1
									return l.Layout(gtx)
								})
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									l := label(a.th, m.Desc, Fs12, ColTx2)
									l.MaxLines = 1
									return l.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return monoLabel(a.th, m.Key, Fs11, ColTx3).Layout(gtx)
							}),
						)
					}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp5}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "本机 mock 靶站（白名单内授权目标）").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											btn := mockButton(a)
											return btn.Layout(gtx)
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												txt := "点「探测」检查 mock 靶站是否已起"
												if mockPro {
													txt = map[bool]string{
														true:  "mock 靶站可达：127.0.0.1:8799",
														false: "mock 靶站不可达——在仓库根跑 python tests/mock_server.py",
													}[mock]
												}
												return monoLabel(a.th, txt, Fs12, statusProbe(mock, mockPro)).Layout(gtx)
											})
										}),
									)
								})
							}),
						)
					})
				})
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "数据落在哪").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(a.th,
										fmt.Sprintf("扫描产物 out\\：        %s", filepath.Join(a.sess.RepoRoot, "out")),
										Fs12, ColTx2).Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(a.th,
										fmt.Sprintf("任务库/日志 data：     %s", a.sess.DataDir),
										Fs12, ColTx2).Layout(gtx)
								})
							}),
						)
					})
				})
			})
		}),
	)
}

// mockButton 探测按钮（次按钮观感：s3 底）。
func mockButton(a *appUI) material.ButtonStyle {
	btn := material.Button(a.th.Theme, &a.mockBtn, "探测")
	btn.Background = ColS3
	btn.Color = ColTx1
	btn.CornerRadius = R2
	return btn
}

// statusProbe 探测结果的文字颜色。
func statusProbe(ok, probed bool) colorNRGBA {
	if !probed {
		return ColTx3
	}
	if ok {
		return ColOk
	}
	return ColWarn
}
