package ui

import (
	"fmt"
	"path/filepath"

	"gioui.org/layout"
	"gioui.org/widget/material"
)

// pageSettings 设置页：解释器自检 / 数据目录 / 关于。
// 整页包在持久 List 里滚动（与工具页同款）：四卡+标题静态高度已逼近一屏，
// 裸 Flex 平铺时窗口偏矮或缩放 >100% 「关于」卡被底边裁掉且无法滚到。
func (a *appUI) pageSettings(gtx layout.Context) layout.Dimensions {
	blocks := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "设置").Layout(gtx)
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.pythonCard(gtx)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.goEngineCard(gtx)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.outputCard(gtx)
			})
		},
		func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4, Bottom: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return a.aboutCard(gtx)
			})
		},
	}
	a.settingsList.Axis = layout.Vertical
	return a.settingsList.Layout(gtx, len(blocks), func(gtx layout.Context, i int) layout.Dimensions {
		return blocks[i](gtx)
	})
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
								return focusOutline(gtx, &a.checkBtn, btn.Layout(gtx), R2)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(a.th.Theme, &a.saveBtn, "保存并生效")
									return focusOutline(gtx, &a.saveBtn, btn.Layout(gtx), R2)
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
									if a.pyProbeBusy {
										txt, col = "自检中…", ColTx3
									} else if a.pyResult != "" {
										// 回执按成败分档（曾固定中性黑，保存失败
										// 「有 N 个任务正在运行…」无错误红）
										txt, col = a.pyResult, a.pyResultCol
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

// goEngineCard Go 引擎（基线检查执行器 recon-go.exe）路径 + 自检 + 保存。
// 引擎缺失时给构建命令，不静默失败（ksubdomain 静默失败教训）。
func (a *appUI) goEngineCard(gtx layout.Context) layout.Dimensions {
	goPath, _, goFound, goProbed := a.env.goSnapshot()
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return sectionLabel(a.th, "Go 引擎（基线检查跑 engine-go/recon-go.exe）").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return inputWell(gtx, a.th, &a.goEd, Fs14, "recon-go.exe 绝对路径（留空用仓库 engine-go 目录探测）")
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(a.th.Theme, &a.goCheckBtn, "自检")
								btn.Background = ColS3
								btn.Color = ColTx1
								btn.CornerRadius = R2
								return focusOutline(gtx, &a.goCheckBtn, btn.Layout(gtx), R2)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(a.th.Theme, &a.goSaveBtn, "保存并生效")
									return focusOutline(gtx, &a.goSaveBtn, btn.Layout(gtx), R2)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									txt, col := "尚未自检", ColTx3
									if !goProbed {
										// 后台自检未回的中间态：显「检测中…」不误报
										//（曾在此 1~2 秒窗口直接判「未找到（需先构建）」）
										txt, col = "检测中…", ColTx3
									} else if goFound {
										txt, col = "已探测到："+goPath, ColOk
									} else {
										txt, col = "未找到（需先构建，见下方指引）", ColWarn
									}
									switch {
									case a.goProbeBusy:
										txt, col = "自检中…", ColTx3
									case a.goResult != "":
										// 回执按成败分档（同 Python 卡）
										txt, col = a.goResult, a.goResultCol
									}
									l := monoLabel(a.th, txt, Fs12, col)
									l.MaxLines = 5 // 构建指引是必达文案， Gio 截断无省略号，放宽防裁尾
									return l.Layout(gtx)
								})
							}),
						)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return monoLabel(a.th, "构建命令：进入仓库 engine-go 目录执行 go build -o recon-go.exe .", Fs11, ColTx3).Layout(gtx)
					})
				}),
			)
		})
	})
}

// outputCard 输出目录只读展示（路径由仓库根决定，不在界面里改）。
func (a *appUI) outputCard(gtx layout.Context) layout.Dimensions {
	outDir := filepath.Join(a.sess.RepoRoot, "out")
	evDir := filepath.Join(a.sess.DataDir, "evidence")
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return sectionLabel(a.th, "输出目录（扫描产物与证据包落点，只读展示）").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return monoLabel(a.th, "扫描产物："+outDir, Fs12, ColTx1).Layout(gtx)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return monoLabel(a.th, "证据包导出："+evDir, Fs12, ColTx1).Layout(gtx)
					})
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return monoLabel(a.th, "产物目录名按目标清洗生成（与引擎同名规则），结果页可一键导出 zip 证据包", Fs11, ColTx3).Layout(gtx)
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
		"扫描引擎以子进程方式运行仓库自带的 Python 流水线，目标本地输入、结果本地出数。",
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
