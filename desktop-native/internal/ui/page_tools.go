package ui

import (
	"fmt"
	"image"
	"os"
	"path/filepath"

	"gioui.org/layout"
	"gioui.org/unit"
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
				return a.depsCard(gtx)
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

// depsCard 外部依赖状态：Python、依赖、引擎脚本、mock 靶站、产物目录。
func (a *appUI) depsCard(gtx layout.Context) layout.Dimensions {
	_, ver, found, deps, mock, probed, mockPro := a.env.snapshot()
	pyPath, pyErr := a.sess.Runner.ResolvePython()
	engineOK := pyErr == nil
	if _, statErr := os.Stat(filepath.Join(a.sess.RepoRoot, "src", "recon.py")); statErr != nil {
		engineOK = false
	}
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
								if !probed && !mockPro {
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
								verdict, ok := "Python 未找到——去设置页填路径", false
								if found {
									verdict, ok = ver, true
									if !deps {
										verdict, ok = ver+"（缺 requests/yaml）", false
									}
								}
								return a.depRow(gtx, "Python 解释器", verdict, ok, probed, pyPath)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return a.depRow(gtx, "扫描引擎 src/recon.py",
										map[bool]string{true: "在仓库根就位", false: "未找到（工作目录必须能向上找到仓库根）"}[engineOK],
										engineOK, true, filepath.Join(a.sess.RepoRoot, "src", "recon.py"))
								})
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
