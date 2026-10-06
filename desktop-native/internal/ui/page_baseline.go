package ui

// page_baseline.go —— 第六页「暴露面」：域名暴露面基线体检仪表盘。
// 输入目标 → 「一键跑全部检查」（CreateTask(target,"baseline","")，页面本身
// 不直接起进程，全部走既有 CreateTask 校验链）→ 8 检查分区卡逐检查展示
// 结论/风险/摘要/原始 JSON（折叠）。
//
// 数据来源两条腿：
//   - 运行态：最新基线任务的进度事件流（baselineEventStates，逐检查点亮）；
//   - 产物态：outDirFor 三方同名目录里的 <check>.json（LoadBaselineProducts，
//     包络契约 = engine-go baseline/result.go 冻结 schema）。
//
// 三态：空=全部「未运行」空卡 + 引导语；载=「检查中…/排队中」逐检查点亮；
// 错=CreateTask 错误横条 / Go 引擎缺失构建指引 / 检查级失败红字（fail 事件
// 不中断其余检查的语义在 UI 可见：个别卡红、其余卡照常推进）。
//
// 布局纪律：卡片内容全部拆成「返回单行 FlexChild」的小助手（每层至多两重
// 闭包），闭包配对错位是本文件初版真实咬过人的坑（gofmt 报 396 行括号失衡）。

import (
	"fmt"
	"image"
	"path/filepath"
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"recon-native/internal/store"
	"recon-native/internal/whitelist"
)

// goEngineMissingHint Go 引擎缺失的显式指引（不静默失败；设置页与仪表盘共用）。
func goEngineMissingHint() string {
	return "未找到 Go 引擎 recon-go.exe（基线检查执行器）。构建：进入仓库 engine-go 目录执行 " +
		"go build -o recon-go.exe . ；或在设置页填入 recon-go.exe 绝对路径后「保存并生效」"
}

// normalizedBaselineTarget 当前输入目标的归一化结果（与 CreateTask 同一条
// whitelist.Check → normalizeTarget 链，页面读取产物用的目录键与任务执行
// 目标一致）。输入为空/格式非法返回 ""（页面维持空态，不猜）。
func (a *appUI) normalizedBaselineTarget() string {
	key, _ := a.baselineTargetKey()
	return key
}

// baselineTargetKey 归一化键 + 非法原因（输入非空但格式非法时 reason 非空，
// 输入井下方即时提示——此前静默退回空态引导卡，要等点按钮才见红条）。
func (a *appUI) baselineTargetKey() (key, reason string) {
	raw := strings.TrimSpace(a.baseTargetEd.Text())
	if raw == "" {
		return "", ""
	}
	k, err := whitelist.Check(raw)
	if err != nil {
		return "", "目标格式：应为域名（不含协议和端口）"
	}
	n, err := normalizeTarget("baseline", k, raw)
	if err != nil {
		return "", "目标格式：应为域名（不含协议和端口）"
	}
	return n, ""
}

// baseTaskRunning 当前目标的最新基线任务是否在跑（queued/running 相位判定）。
func (a *appUI) baseTaskRunning() bool {
	return a.baseStatus == store.StatusRunning || a.baseStatus == store.StatusCreated
}

// baseTaskRunningSel 指定状态是否为运行中（结果页选中任务快照刷新判定）。
func (a *appUI) baseTaskRunningSel(status string) bool {
	return status == store.StatusRunning || status == store.StatusCreated
}

// pollBaseline 400ms 节拍刷新（update 调用）：目标变更重读产物快照；
// 最新基线任务的事件流逐检查点亮；运行中产物随拍刷新（引擎逐检查落盘）。
func (a *appUI) pollBaseline() {
	// 横条生命周期锚：成功/错误横条属于「一次输入的尝试」（成功横条带
	// 当时目标的新任务号），目标输入变化即失效——旧目标任务号挂在别的
	// 目标下易误读（验收 p6-cards78）。点击当帧 raw 与 baseLastInput 已
	// 同步，不会误清刚设置的横条。
	raw := strings.TrimSpace(a.baseTargetEd.Text())
	if raw != a.baseLastInput {
		a.baseLastInput = raw
		a.baseErr, a.baseOK, a.baseTerm, a.baseTermID = "", "", "", ""
	}
	key := a.normalizedBaselineTarget()
	if key == "" {
		a.baseTarget, a.baseStates, a.baseEvents = "", nil, nil
		a.baseRunID, a.baseStatus = "", ""
		return
	}
	if key != a.baseTarget {
		a.baseTarget = key
		a.baseStates = LoadBaselineProducts(a.sess.RepoRoot, key)
		a.baseEvents, a.baseRunID, a.baseStatus = nil, "", ""
	}
	// 该目标最新的基线任务（页面发起与结果页发起同等对待）
	var best *store.Task
	for i := range a.tasks {
		t := a.tasks[i]
		if t.Cmd == "baseline" && t.Target == key {
			if best == nil || t.CreatedAt > best.CreatedAt {
				best = &a.tasks[i]
			}
		}
	}
	if best == nil {
		return
	}
	a.baseEvents = baselineEventStates(best.Progress)
	a.baseRunID = best.ID
	a.baseStatus = best.Status
	if a.baseTaskRunning() {
		a.baseStates = LoadBaselineProducts(a.sess.RepoRoot, key)
		return
	}
	// 任务终态呈现：引擎秒退（recon-go.exe 损坏等）或被 Esc 停止时，8 张卡
	// 全停在「未运行」，页面此前无任何反馈、「已开始」横条常驻误导——
	// 终态横条写一次（按任务 id 去重，400ms 节拍不重刷），并清掉「已开始」。
	if a.baseOK != "" {
		a.baseOK = ""
	}
	switch best.Status {
	case store.StatusFail:
		if a.baseTermID != best.ID {
			a.baseTermID = best.ID
			a.baseTerm = "基线检查失败——去结果页看该任务的过程记录"
		}
	case store.StatusStopped:
		if a.baseTermID != best.ID {
			a.baseTermID = best.ID
			a.baseTerm = "基线检查已停止——去结果页看该任务的过程记录"
		}
	}
}

// baseJSONClick 返回卡片折叠钮自己的 Clickable（每帧恰一次点击处理）。
func (a *appUI) baseJSONClick(key string) *widget.Clickable {
	c, ok := a.baseJSONBtns[key]
	if !ok {
		c = &widget.Clickable{}
		a.baseJSONBtns[key] = c
	}
	return c
}

// pageBaseline 暴露面仪表盘页。
func (a *appUI) pageBaseline(gtx layout.Context) layout.Dimensions {
	head := layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return head.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return titleLabel(a.th, "暴露面").Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return label(a.th, "域名暴露面基线体检 · 8 项检查一键跑 · 零凭据", Fs12, ColTx3).Layout(gtx)
					})
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp3}.Layout(gtx, a.baselineInputCard)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp4, Bottom: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return sectionLabel(a.th, "检查项（8）").Layout(gtx)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			if a.baseTarget == "" || len(a.baseStates) == 0 {
				return emptyHint(gtx, a.th, "输入目标域名后一键体检；这里会逐检查显示结论、缺失项与风险明细")
			}
			list := a.baseList // 持久 List：卡片滚动位置跨帧存活
			list.Axis = layout.Vertical
			return list.Layout(gtx, len(a.baseStates), func(gtx layout.Context, i int) layout.Dimensions {
				return layout.Inset{Bottom: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return a.baselineCard(gtx, a.baseStates[i])
				})
			})
		}),
	)
}

// baselineInputCard 目标输入 + 一键跑 + 错误/成功/终态横条 + 引擎缺失指引。
func (a *appUI) baselineInputCard(gtx layout.Context) layout.Dimensions {
	rows := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return sectionLabel(a.th, "目标域名（不含协议和端口，如 xycovo.com）").Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return inputWell(gtx, a.th, &a.baseTargetEd, Fs14, "输入目标域名")
			})
		}),
	}
	// 输入非空但格式非法：井下即时提示原因（此前静默退回空态，要等点按钮才见红条）
	if key, reason := a.baselineTargetKey(); key == "" && reason != "" {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return label(a.th, reason, Fs11, ColTx3).Layout(gtx)
			})
		}))
	}
	rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: Sp3}.Layout(gtx, a.baselineRunButton)
	}))
	if _, err := a.sess.Runner.ResolveGoEngine(); err != nil {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return banner(gtx, a.th, goEngineMissingHint(), ColWarnBg, ColWarn)
			})
		}))
	}
	if a.baseErr != "" {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return errBanner(gtx, a.th, a.baseErr)
			})
		}))
	}
	if a.baseOK != "" {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return okBanner(gtx, a.th, a.baseOK)
			})
		}))
	}
	if a.baseTerm != "" {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// 失败红 / 停止橙：终态横条（任务失败或被停后页面唯一的显性反馈）
				if strings.Contains(a.baseTerm, "失败") {
					return errBanner(gtx, a.th, a.baseTerm)
				}
				return banner(gtx, a.th, a.baseTerm, ColWarnBg, ColWarn)
			})
		}))
	}
	if a.baseTarget != "" && a.baseRunID == "" {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return monoLabel(a.th, "该目标还没有基线任务——点上方按钮开始体检", Fs11, ColTx3).Layout(gtx)
			})
		}))
	}
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp3, Bottom: Sp3, Left: Sp4, Right: Sp4}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		})
	})
}

// baselineRunButton 一键跑按钮（运行中真禁用：Disabled 上下文不投递事件 +
// update 层 running 守卫双保险，material 自动灰化混色，点击无按压反馈）。
func (a *appUI) baselineRunButton(gtx layout.Context) layout.Dimensions {
	running := a.baseTaskRunning()
	txt, bg, fg := "一键跑全部检查", ColAcc, ColAccInk
	if running {
		txt, bg, fg = "检查进行中…", ColS1, ColTx3
		gtx = gtx.Disabled()
	}
	btn := material.Button(a.th.Theme, &a.baseRunBtn, txt)
	btn.Background = bg
	btn.Color = fg
	btn.CornerRadius = R2
	return focusOutline(gtx, &a.baseRunBtn, btn.Layout(gtx), R2)
}

// baselineCard 单检查分区卡：顶部结论色条（level→Bg 族）+ 状态行 +
// 结论/风险明细/摘要/原始 JSON（折叠）。
func (a *appUI) baselineCard(gtx layout.Context, st BaselineCheckState) layout.Dimensions {
	phase := baselineCheckPhase(st, a.baseEvents[st.Key], a.baseTaskRunning())
	stripBg, stripFg := ColS1, ColTx3 // notrun/queued 默认族
	switch phase {
	case "conclusion":
		stripBg, stripFg = baselineLevelColor(st.Res.ConclusionLevel)
	case "failed":
		stripBg, stripFg = ColErrBg, ColErr
	case "running":
		stripBg, stripFg = ColAccBg, ColAccHi
	case "skipped":
		stripBg, stripFg = ColWarnBg, ColWarn
	}
	rows := append([]layout.FlexChild{baselineStrip(stripBg)}, a.baselineCardBody(st, phase, stripFg)...)
	return card(gtx, ColS2, R3, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

// baselineStrip 结论色条（level→Bg 族，6dp 横条）。
func baselineStrip(bg colorNRGBA) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(6))
		size := image.Pt(gtx.Constraints.Min.X, h)
		defer clipRect(gtx, size)()
		paintFill(gtx, bg)
		return layout.Dimensions{Size: size}
	})
}

// baselineCardBody 卡片内容行集（状态行 + 各条件块）。
func (a *appUI) baselineCardBody(st BaselineCheckState, phase string, fg colorNRGBA) []layout.FlexChild {
	rows := []layout.FlexChild{a.baselineCardHeader(st, phase, fg)}
	inset := layout.Inset{Top: Sp2, Left: Sp3} // 内容缩进回归 4 的倍数间距律（曾 14dp 魔法数）
	switch phase {
	case "conclusion":
		rows = append(rows,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return baselineConclusionBlock(gtx, a.th, st, fg)
				})
			}),
		)
		if len(st.Res.Risks) > 0 {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return baselineRisksBlock(gtx, a.th, st.Res.Risks)
				})
			}))
		}
		if len(st.Res.Summary) > 0 {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return baselineSummaryBlock(gtx, a.th, st.Res.Summary)
				})
			}))
		}
	case "failed":
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				l := label(a.th, "执行失败："+st.Res.Error, Fs12, ColErr)
				l.MaxLines = 3
				return l.Layout(gtx)
			})
		}))
		if len(st.Res.Risks) > 0 {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return baselineRisksBlock(gtx, a.th, st.Res.Risks)
				})
			}))
		}
	case "notrun", "queued":
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return label(a.th, st.Desc, Fs12, ColTx3).Layout(gtx)
			})
		}))
	}
	if a.baseJSONOpen[st.Key] && st.Loaded {
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return baselineRawBlock(gtx, a.th, st, a.baseTarget)
			})
		}))
	}
	return rows
}

// baselineCardHeader 状态行：LED + 中文名 + 相位 + 检查键 + 原始 JSON 折叠钮。
func (a *appUI) baselineCardHeader(st BaselineCheckState, phase string, fg colorNRGBA) layout.FlexChild {
	return layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		header := layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}
		return header.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return baselineLED(gtx, phase, st.Res.ConclusionLevel)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return label(a.th, st.Label, Fs13, ColTx1).Layout(gtx)
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return label(a.th, baselinePhaseLabel(phase), Fs12, fg).Layout(gtx)
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Left: Sp2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return monoLabel(a.th, st.Key, Fs11, ColTx3).Layout(gtx)
				})
			}),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				// 占位必须返回分配到的 Min 尺寸：返回零尺寸会被 Flex 按零宽
				// 记账，右侧折叠钮贴回检查键（实测截图钉住）。
				return layout.Dimensions{Size: image.Pt(gtx.Constraints.Min.X, 0)}
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.baselineJSONToggle(gtx, st.Key)
			}),
		)
	})
}

// baselineJSONToggle 原始 JSON 折叠开关小钮。
func (a *appUI) baselineJSONToggle(gtx layout.Context, key string) layout.Dimensions {
	txt := "原始 JSON ▸"
	if a.baseJSONOpen[key] {
		txt = "原始 JSON ▾"
	}
	c := a.baseJSONClick(key)
	// 折叠钮与结果页分页钮同族同宽 84dp（曾 96dp，同族小钮三种宽并存）
	gtx.Constraints.Min.X = gtx.Dp(unit.Dp(84))
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(24))
	bl := material.ButtonLayout(a.th.Theme, c)
	bl.Background = ColS3
	bl.CornerRadius = R2
	dims := bl.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return label(a.th, txt, Fs11, ColTx2).Layout(gtx)
		})
	})
	return focusOutline(gtx, c, dims, R2)
}

// baselineConclusionBlock 结论行：[level] 文本 + 生成时间。
func baselineConclusionBlock(gtx layout.Context, th *Theme, st BaselineCheckState, fg colorNRGBA) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return label(th, "["+st.Res.ConclusionLevel+"] "+st.Res.ConclusionText, Fs12, fg).Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: Sp1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return monoLabel(th, "生成于 "+st.Res.GeneratedAt, Fs11, ColTx3).Layout(gtx)
			})
		}),
	)
}

// baselineRisksBlock 风险明细（level 着色，最多 3 行/条）。
func baselineRisksBlock(gtx layout.Context, th *Theme, risks []BaselineRisk) layout.Dimensions {
	out := make([]layout.FlexChild, 0, len(risks))
	for _, r := range risks {
		r := r
		out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			_, fg := baselineLevelColor(r.Level)
			txt := "· [" + r.Level + "] " + r.Title
			if r.Detail != "" {
				txt += " — " + r.Detail
			}
			l := label(th, txt, Fs12, fg)
			l.MaxLines = 3
			return l.Layout(gtx)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
}

// baselineSummaryBlock 引擎自产可读摘要行。
func baselineSummaryBlock(gtx layout.Context, th *Theme, summary []string) layout.Dimensions {
	out := make([]layout.FlexChild, 0, len(summary))
	for _, s := range summary {
		s := s
		out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := monoLabel(th, s, Fs11, ColTx2)
			l.MaxLines = 2
			return l.Layout(gtx)
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, out...)
}

// baselineRawBlock 原始 JSON（凹井展示；超长截断并注明完整文件位置）。
func baselineRawBlock(gtx layout.Context, th *Theme, st BaselineCheckState, target string) layout.Dimensions {
	return card(gtx, ColS0, R2, func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Inset{Top: Sp2, Bottom: Sp2, Left: Sp3, Right: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			raw := st.Res.RawJSON
			const cap = 2000
			if len(raw) > cap {
				raw = raw[:cap] + fmt.Sprintf("\n…（截断，完整文件 %d 字节：out/%s/%s.json）",
					len(st.Res.RawJSON), filepath.Base(target), st.Key)
			}
			return monoLabel(th, raw, Fs11, ColTx2).Layout(gtx)
		})
	})
}

// baselineLED 相位状态点（8dp 实心圆，idle 相位用 Tx3 族表达待命）。
func baselineLED(gtx layout.Context, phase, level string) layout.Dimensions {
	d := gtx.Dp(unit.Dp(8))
	size := image.Pt(d, d)
	defer clipCircle(gtx, d)()
	paintFill(gtx, baselinePhaseColor(phase, level))
	return layout.Dimensions{Size: size}
}
