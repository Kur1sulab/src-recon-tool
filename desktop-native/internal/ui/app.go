package ui

import (
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"recon-native/internal/store"
)

// 五页信息架构（原「新建侦察」页定名「新建任务」）。
const (
	pageDashboard = iota
	pageNewTask
	pageResults
	pageTools
	pageSettings
)

var pageNames = []string{"仪表盘", "新建任务", "结果", "工具", "设置"}

// envInfo 环境自检快照（后台 goroutine 采样，界面读快照）。
type envInfo struct {
	mu      sync.Mutex
	pyPath  string
	pyVer   string
	found   bool
	depsOK  bool
	mockOK  bool
	probed  bool
	mockPro bool
}

func (e *envInfo) snapshot() (path, ver string, found, deps, mock, probed, mockPro bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pyPath, e.pyVer, e.found, e.depsOK, e.mockOK, e.probed, e.mockPro
}

func (e *envInfo) set(path, ver string, found, deps, mock bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pyPath, e.pyVer, e.found, e.depsOK, e.mockOK = path, ver, found, deps, mock
	e.probed = true
}

func (e *envInfo) setMock(ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mockOK, e.mockPro = ok, true
}

// appUI 主界面状态。全部状态只在窗口事件循环（单 goroutine）里读写，
// envInfo 例外（后台自检 goroutine 经锁回写）。
type appUI struct {
	sess *Session
	th   *Theme
	env  envInfo

	page    int
	navBtns []widget.Clickable

	// 新建任务页
	targetEd  widget.Editor
	argsEd    widget.Editor
	moduleSel widget.Enum
	startBtn  widget.Clickable
	newErr    string
	newOK     string

	// 结果页
	tasks      []store.Task
	selID      string
	taskClicks map[string]*widget.Clickable
	stopBtn    widget.Clickable
	lastPoll   time.Time

	// 工具页
	mockBtn   widget.Clickable
	mockState string

	// 设置页
	pyEd     widget.Editor
	checkBtn widget.Clickable
	saveBtn  widget.Clickable
	pyResult string
}

// Run 启动主窗口（阻塞至窗口关闭）。
func Run() error {
	dataDir := dataDirPath()
	for _, sub := range []string{"logs", "progress"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o755); err != nil {
			return fmt.Errorf("初始化数据目录失败: %w", err)
		}
	}
	sess, err := NewSession(findRepoRoot(), dataDir, os.Getenv("RECON_PYTHON"))
	if err != nil {
		return err
	}
	defer sess.Runner.StopAll()

	w := new(app.Window)
	w.Option(app.Title("信息收集工具"), app.Size(unit.Dp(1180), unit.Dp(760)))

	a := newAppUI(sess)
	a.th = NewTheme()
	// 环境自检放后台：不挡首帧
	go func() {
		py, _ := a.sess.Runner.ResolvePython()
		found, ver, deps := a.sess.Runner.ProbePython()
		a.env.set(py, ver, found, deps, mockReachable())
	}()

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			a.sess.Runner.StopAll()
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			a.update(gtx)
			a.layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func newAppUI(sess *Session) *appUI {
	a := &appUI{
		sess:       sess,
		navBtns:    make([]widget.Clickable, len(pageNames)),
		taskClicks: map[string]*widget.Clickable{},
	}
	a.moduleSel.Value = "all"
	a.targetEd.SingleLine = true
	a.argsEd.SingleLine = true
	a.pyEd.SingleLine = true
	a.pyEd.SetText(a.sess.resolvePythonOrEmpty())
	return a
}

// update 处理一帧内的全部交互。
func (a *appUI) update(gtx layout.Context) {
	// 侧栏导航
	for i := range a.navBtns {
		if a.navBtns[i].Clicked(gtx) {
			a.page = i
		}
	}
	// 结果页数据节流刷新（400ms 一次，避免每帧拷贝任务库）
	if time.Since(a.lastPoll) > 400*time.Millisecond {
		a.lastPoll = time.Now()
		a.tasks = a.sess.Tasks()
		// 建任务后自动跳结果页由 Start 完成；这里兜底选中失效任务清空
		if _, ok := a.sess.Task(a.selID); !ok && a.selID != "" {
			if len(a.tasks) > 0 {
				a.selID = a.tasks[0].ID
			} else {
				a.selID = ""
			}
		}
	}

	// 新建任务：开始
	if a.startBtn.Clicked(gtx) {
		a.newErr, a.newOK = "", ""
		id, err := a.sess.CreateTask(a.targetEd.Text(), a.moduleSel.Value, a.argsEd.Text())
		if err != nil {
			a.newErr = err.Error()
		} else {
			a.newOK = "任务已开始：" + id
			a.selID = id
			a.page = pageResults
		}
	}

	// 结果页：停止选中任务
	if a.stopBtn.Clicked(gtx) && a.selID != "" {
		if err := a.sess.StopTask(a.selID); err != nil {
			a.newErr = err.Error()
			a.page = pageResults
		}
	}

	// 工具页：mock 靶站探测（白名单内本机目标）
	if a.mockBtn.Clicked(gtx) {
		ok := mockReachable()
		a.env.setMock(ok)
		a.mockState = map[bool]string{true: "mock 靶站可达（127.0.0.1:8799）", false: "mock 靶站不可达——先用 python tests/mock_server.py 起靶站"}[ok]
	}

	// 设置页：自检 / 保存解释器路径
	if a.checkBtn.Clicked(gtx) {
		found, ver, deps := a.sess.Runner.ProbePython()
		switch {
		case !found:
			a.pyResult = "未找到可用 Python——填绝对路径后点「保存并生效」"
		case !deps:
			a.pyResult = ver + "；缺少依赖 requests/yaml，先 pip install -r requirements.txt"
		default:
			a.pyResult = ver + "；依赖齐全，可以扫描"
		}
	}
	if a.saveBtn.Clicked(gtx) {
		if err := a.sess.SetPythonPath(a.pyEd.Text()); err != nil {
			a.pyResult = err.Error()
		} else {
			a.pyResult = "已切换解释器：" + a.pyEd.Text()
		}
	}
}

// ── 整体布局：顶栏 + 侧栏 + 主区 ──

func (a *appUI) layout(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(a.topbar),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return card(gtx, ColS1, 0, a.sidebar)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return card(gtx, ColS0, 0, a.mainArea)
				}),
			)
		}),
	)
}

// topbar 顶栏：产品名 + 铭牌。
func (a *appUI) topbar(gtx layout.Context) layout.Dimensions {
	h := gtx.Dp(TopH)
	gtx.Constraints.Min.Y = h
	return layout.Stack{Alignment: layout.W}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			return fillRect(gtx, ColS1)
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(SideW)
					t := titleLabel(a.th, "信息收集工具")
					return layout.Inset{Left: PadX}.Layout(gtx, t.Layout)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					l := label(a.th, "专精信息收集 · 纯本地运行 · 无 AI · 不联网上报", Fs11, ColTx3)
					return l.Layout(gtx)
				}),
			)
		}),
		layout.Stacked(hairlineAtBottom(gtx, ColLn1)),
	)
}

// hairlineAtBottom 在栈底画一条发丝线。
func hairlineAtBottom(gtx layout.Context, c colorNRGBA) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		h := gtx.Dp(unit.Dp(1))
		size := image.Pt(gtx.Constraints.Min.X, h)
		defer clipRect(gtx, size)()
		paintFill(gtx, c)
		return layout.Dimensions{Size: size}
	}
}

// sidebar 侧栏导航（五页）。
func (a *appUI) sidebar(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Min.X = gtx.Dp(SideW)
	gtx.Constraints.Max.X = gtx.Dp(SideW)
	return layout.Inset{Top: Sp3}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, navItems(a)...)
	})
}

func navItems(a *appUI) []layout.FlexChild {
	out := make([]layout.FlexChild, 0, len(pageNames))
	for i, name := range pageNames {
		i, name := i, name
		out = append(out, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return a.navItem(gtx, i, name)
		}))
	}
	return out
}

// navItem 单个导航项：默认 s1/次文，悬停 s3，选中 acc-bg/亮青。
func (a *appUI) navItem(gtx layout.Context, i int, name string) layout.Dimensions {
	btn := &a.navBtns[i]
	active := a.page == i
	bg, fg := ColS1, ColTx2
	switch {
	case active:
		bg, fg = ColAccBg, ColAccHi
	case btn.Hovered():
		bg, fg = ColS3, ColTx1
	}
	gtx.Constraints.Min.X = gtx.Dp(SideW)
	gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(40))
	bl := material.ButtonLayout(a.th.Theme, btn)
	bl.Background = bg
	bl.CornerRadius = 0
	return bl.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// 选中轨：3dp 品牌青竖条
				if !active {
					return layout.Dimensions{Size: image.Pt(gtx.Dp(unit.Dp(3)), gtx.Dp(unit.Dp(40)))}
				}
				w := gtx.Dp(unit.Dp(3))
				size := image.Pt(w, gtx.Dp(unit.Dp(40)))
				defer clipRect(gtx, size)()
				paintFill(gtx, ColAcc)
				return layout.Dimensions{Size: size}
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := label(a.th, name, Fs13, fg)
				if active {
					l.Font.Weight = font.SemiBold
				}
				return layout.Inset{Left: Sp3}.Layout(gtx, l.Layout)
			}),
		)
	})
}

// mainArea 主区：按当前页分发。
func (a *appUI) mainArea(gtx layout.Context) layout.Dimensions {
	return layout.UniformInset(PadX).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		switch a.page {
		case pageDashboard:
			return a.pageDashboard(gtx)
		case pageNewTask:
			return a.pageNewTask(gtx)
		case pageResults:
			return a.pageResults(gtx)
		case pageTools:
			return a.pageTools(gtx)
		case pageSettings:
			return a.pageSettings(gtx)
		}
		return layout.Dimensions{}
	})
}

// ── 通用表格（表头 + 斑马纹数据行，List 虚拟化）──

// table 表头 + n 行数据。widths 为相对权重；cell 返回该行各列文本。
func table(gtx layout.Context, th *Theme, n int, headers []string, widths []float32, cell func(gtx layout.Context, i int) []string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Constraints.Max.X
			return tableRow(gtx, th, headers, widths, true)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return hairline(gtx, ColLn1)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			list := layout.List{Axis: layout.Vertical}
			return list.Layout(gtx, n, func(gtx layout.Context, i int) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				if i%2 == 1 {
					return layout.Stack{Alignment: layout.W}.Layout(gtx,
						layout.Expanded(func(gtx layout.Context) layout.Dimensions {
							return fillRect(gtx, ColZebra)
						}),
						layout.Stacked(func(gtx layout.Context) layout.Dimensions {
							return tableRow(gtx, th, cell(gtx, i), widths, false)
						}),
					)
				}
				return tableRow(gtx, th, cell(gtx, i), widths, false)
			})
		}),
	)
}

// tableRow 单行：加权横排单元。
func tableRow(gtx layout.Context, th *Theme, cells []string, widths []float32, header bool) layout.Dimensions {
	h := gtx.Dp(RowH)
	gtx.Constraints.Min.Y = h
	col := ColTx1
	size := Fs12
	weight := font.Normal
	if header {
		col = ColTx2
		size = Fs11
		weight = font.Medium
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		rowCells(th, cells, widths, size, col, weight, header)...)
}

func rowCells(th *Theme, cells []string, widths []float32, size unit.Sp, col colorNRGBA, weight font.Weight, header bool) []layout.FlexChild {
	out := make([]layout.FlexChild, 0, len(cells))
	for ci, text := range cells {
		w := float32(1)
		if ci < len(widths) {
			w = widths[ci]
		}
		out = append(out, layout.Flexed(w, func(gtx layout.Context) layout.Dimensions {
			var l material.LabelStyle
			if header {
				l = label(th, text, size, col)
			} else {
				l = monoLabel(th, text, size, col)
			}
			l.Font.Weight = weight
			return layout.Inset{Right: Sp2}.Layout(gtx, l.Layout)
		}))
	}
	return out
}
