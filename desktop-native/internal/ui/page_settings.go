package ui

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/widget/material"

	"recon-native/internal/whitelist"
)

// pageSettings 设置页：解释器自检 / 数据目录 / 白名单 / 关于。
func (a *appUI) pageSettings(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "设置").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.pythonCard(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.whitelistCard(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.aboutCard(gtx)
			})
		}),
	)
}

// pythonCard 解释器路径 + 自检 + 保存。
func (a *appUI) pythonCard(gtx layout.Context) layout.Dimensions {
	path, ver, found, deps, _, probed, _ := a.env.snapshot()
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return sectionLabel(a.th, "Python 解释器（扫描引擎靠它跑 recon.py）").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return inputWell(gtx, a.th, &a.pyEd, Fs14, "python.exe 绝对路径")
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(a.th.Theme, &a.checkBtn, "自检")
								btn.Background = ColS3
								btn.Color = ColTx1
								btn.CornerRadius = R2
								return btn.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(a.th.Theme, &a.saveBtn, "保存并生效")
									return btn.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									txt, col := "尚未自检", ColTx3
									if probed {
										switch {
										case !found:
											txt, col = "解释器不可用", ColErr
										case !deps:
											txt, col = ver+"（缺 requests/yaml）", ColWarn
										default:
											txt, col = ver+"（依赖齐全）", ColOk
										}
									}
									if a.pyResult != "" {
										txt, col = a.pyResult, ColTx1
									}
									l := monoLabel(a.th, txt, Fs12, col)
									l.MaxLines = 2
									return l.Layout(gtx)
								})
							}),
						)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return monoLabel(a.th, fmt.Sprintf("当前生效：%s", path), Fs11, ColTx3).Layout(gtx)
					})
				}),
			)
		})
	})
}

// whitelistCard 白名单只读展示。
func (a *appUI) whitelistCard(gtx layout.Context) layout.Dimensions {
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return sectionLabel(a.th, "授权目标白名单（硬红线，名单外一律拒绝，不可在此修改）").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						out := make([]layout.FlexChild, 0, len(whitelist.Entries))
						for _, e := range whitelist.Entries {
							e := e
							out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return monoLabel(a.th, e, Fs13, ColTx1).Layout(gtx)
								})
							}))
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
					})
				}),
			)
		})
	})
}

// aboutCard 关于。
func (a *appUI) aboutCard(gtx layout.Context) layout.Dimensions {
	lines := []string{
		"信息收集工具 —— 专精信息收集的桌面工具：子域枚举 / 资产测绘 / 指纹识别 / 敏感路径 / API 面梳理。",
		"纯本地运行：零 AI 功能、无对话组件、不调用任何联网模型、不上报任何遥测数据。",
		"扫描目标只在授权白名单内放行；扫描引擎以子进程方式运行仓库自带的 Python 流水线。",
	}
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return titleLabel(a.th, "关于").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						out := make([]layout.FlexChild, 0, len(lines))
						for _, s := range lines {
							s := s
							out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									l := label(a.th, s, Fs12, ColTx2)
									l.MaxLines = 2
									return l.Layout(gtx)
								})
							}))
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
					})
				}),
			)
		})
	})
}
