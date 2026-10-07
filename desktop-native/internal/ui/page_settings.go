package ui

import (
	"path/filepath"

	"gioui.org/layout"
)

// pageSettings 设置页：输出目录 / 关于。第 2 步直调重写后引擎内置于程序
// 本体（Python 解释器卡与 recon-go.exe 路径卡随子进程壳一并移除），设置页
// 无路径配置项。整页包在持久 List 里滚动（与工具页同款）。
func (a *appUI) pageSettings(gtx layout.Context) layout.Dimensions {
	blocks := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return titleLabel(a.th, "设置").Layout(gtx)
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
		"扫描引擎内置于程序本体（纯 Go 实现，进程内直调），无需安装 Python 或外部引擎。",
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
