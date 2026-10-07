package ui

import (
	"image"
	"os"
	"path/filepath"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// pageTools 工具页：模块说明 + mock 靶站探测 + 产物目录。
// 页内容比一屏高，包在垂直 List 里滚动——此前一次性 Flex 平铺，
// 底部「数据落在哪」面板被窗口底边截断（真窗口验收 H4）。
func (a *appUI) pageTools(gtx layout.Context) layout.Dimensions {
	mock, mockPro := a.env.snapshot()

	blocks := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "工具").Layout(gtx)
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "扫描模块（八个，全部本地出数）").Layout(gtx)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				out := make([]layout.FlexChild, 0, len(Modules))
				for _, m := range Modules {
					m := m
					out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						// 行间 Sp1：10 行纯文字曾零行距贴死，与同页卡片区密度反差大
						return layout.Inset{Bottom: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
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
						})
					}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			// 分区间距统一 Sp4（首段曾 Sp5，同页三段两种节奏）
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "本机 mock 靶站").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											// 探测中真禁用：事件不投递，右侧结论行显「探测中…」
											if a.mockBusy {
												gtx = gtx.Disabled()
											}
											btn := mockButton(a)
											return focusOutline(gtx, &a.mockBtn, btn.Layout(gtx), R2)
										}),
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												txt := "点「探测」检查 mock 靶站是否已起"
												switch {
												case a.mockState != "": // 探测在后台跑的中间态
													txt = a.mockState
												case mockPro:
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
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.depsCard(gtx)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4, Bottom: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return sectionLabel(a.th, "数据落在哪").Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return kvRow(gtx, a.th, "扫描产物目录", filepath.Join(a.sess.RepoRoot, "out"))
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return kvRow(gtx, a.th, "任务库/日志目录", a.sess.DataDir)
								})
							}),
						)
					})
				})
			})
		},
	}
	// 持久 List：滚动位置跨帧存活（app.go 滚动状态教训的同款修复件——
	// 每帧新建 List 等于每帧清零滚动位置，验收实锤底面板不可达）。
	a.toolsList.Axis = layout.Vertical
	return a.toolsList.Layout(gtx, len(blocks), func(gtx layout.Context, i int) layout.Dimensions {
		return blocks[i](gtx)
	})
}

// mockButton 探测按钮（次按钮观感：s3 底；探测中的 Disabled 在调用点包）。
func mockButton(a *appUI) material.ButtonStyle {
	btn := material.Button(a.th.Theme, &a.mockBtn, "探测")
	btn.Background = ColS3
	btn.Color = ColTx1
	btn.CornerRadius = R2
	return btn
}

// kvRow 两列行：定宽标签 + 等宽路径。曾靠手补空格对齐单行文案——标签含
// 中文时 monoLabel 整串回退比例字体，补位必不齐；两列布局天然对齐。
func kvRow(gtx layout.Context, th *Theme, k, v string) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// 定宽列宽按最宽标签「任务库/日志目录」7 字 + 斜杠 ≈ 90dp 取 4 的倍数
			gtx.Constraints.Min.X = gtx.Dp(unit.Dp(96))
			gtx.Constraints.Max.X = gtx.Constraints.Min.X
			return layout.Inset{Right: Sp2}.Layout(gtx, sectionLabel(th, k).Layout)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := monoLabel(th, v, Fs12, ColTx2)
			l.MaxLines = 1
			return l.Layout(gtx)
		}),
	)
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

// depRow 外部依赖状态一行：名称 + 结论 + 路径（mono）。
func (a *appUI) depRow(gtx layout.Context, name, verdict string, ok, probed bool, path string) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// 状态圆点：ok 绿 / 有问题橙 / 检测中弱注灰
					col := ColTx3
					if probed {
						col = map[bool]colorNRGBA{true: ColOk, false: ColWarn}[ok]
					}
					size := gtx.Dp(unit.Dp(7))
					c := clipCircle(gtx, size)
					defer c()
					paintFill(gtx, col)
					return layout.Inset{Right: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Dimensions{Size: image.Pt(size, size)}
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return label(a.th, name, Fs13, ColTx1).Layout(gtx)
					})
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					l := label(a.th, verdict, Fs12, statusProbe(ok, probed))
					l.MaxLines = 1
					return l.Layout(gtx)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if path == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Left: Sp4, Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := monoLabel(a.th, path, Fs11, ColTx3)
				l.MaxLines = 1
				return l.Layout(gtx)
			})
		}),
	)
}

// depsCard 外部依赖状态：扫描引擎（内置）、mock 靶站、产物目录。
// 第 2 步直调重写后无 Python/引擎脚本依赖项（引擎随程序本体发行）。
func (a *appUI) depsCard(gtx layout.Context) layout.Dimensions {
	mock, mockPro := a.env.snapshot()
	outOK := false
	if info, statErr := os.Stat(filepath.Join(a.sess.RepoRoot, "out")); statErr == nil && info.IsDir() {
		outOK = true
	}

	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return sectionLabel(a.th, "外部依赖状态").Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								if !mockPro {
									return label(a.th, "检测中…", Fs11, ColTx3).Layout(gtx)
								}
								return layout.Dimensions{}
							})
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return a.depRow(gtx, "扫描引擎（内置）", "随程序本体发行，进程内直调，无需安装",
									true, true, "")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return a.depRow(gtx, "本机 mock 靶站",
										map[bool]string{true: "可达（127.0.0.1:8799）", false: "不可达——python tests/mock_server.py 起靶"}[mock],
										mock, mockPro, "http://127.0.0.1:8799")
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return a.depRow(gtx, "产物目录 out/",
										map[bool]string{true: "存在", false: "尚未生成（首次扫描后出现）"}[outOK],
										outOK, true, filepath.Join(a.sess.RepoRoot, "out"))
								})
							}),
						)
					})
				}),
			)
		})
	})
}
