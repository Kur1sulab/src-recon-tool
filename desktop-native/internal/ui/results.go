package ui

import (
	"sort"
	"time"

	"recon-native/internal/store"
)

// ModuleInfo 一个扫描模块的展示元数据（九模块，与 engine.cmdSet 一一对应）。
type ModuleInfo struct {
	Key   string // 传给 recon.py 的子命令
	Label string // 中文名（界面用）
	Desc  string // 一句话说明（工具页/新建任务页用）
}

// Modules 九个扫描模块（顺序即界面排列顺序）。
var Modules = []ModuleInfo{
	{"all", "全部模块", "按顺序跑完整条信息收集流水线"},
	{"subdomain", "子域枚举", "从公开数据源枚举子域并做存活验证"},
	{"paths", "敏感路径", "探测备份文件、后台入口、敏感配置等路径"},
	{"api", "API 面", "梳理 Swagger/OpenAPI 等接口文档与接口端点"},
	{"fingerprint", "指纹识别", "识别 Web 框架、中间件与组件指纹"},
	{"jsintel", "JS 情报", "从页面引用的 JS 里提取端点与线索"},
	{"portscan", "端口扫描", "对目标 IP 做常用端口探测"},
	{"reverse", "IP 反查", "反查 IP 绑定的域名与旁站线索"},
	{"icp", "ICP 备案", "查询域名 ICP 备案主体信息"},
}

// moduleLabel 取模块中文名（未知 key 原样返回；pipeline 是引擎过程事件的前缀）。
func moduleLabel(key string) string {
	if key == "pipeline" {
		return "流水线"
	}
	for _, m := range Modules {
		if m.Key == key {
			return m.Label
		}
	}
	return key
}

// StatusText 任务状态中文名。
func StatusText(status string) string {
	switch status {
	case store.StatusCreated:
		return "已创建"
	case store.StatusRunning:
		return "运行中"
	case store.StatusDone:
		return "已完成"
	case store.StatusFail:
		return "失败"
	case store.StatusStopped:
		return "已停止"
	}
	return status
}

// TaskRow 结果页任务列表的一行。
type TaskRow struct {
	ID        string
	CreatedAt string
	Target    string
	Module    string
	Status    string
	StatusRaw string
}

// TaskRows 把任务列表转成表格行，按创建时间倒序（最新在前，不依赖调用方排序）。
func TaskRows(tasks []store.Task) []TaskRow {
	sorted := make([]store.Task, len(tasks))
	copy(sorted, tasks)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CreatedAt > sorted[j].CreatedAt })
	rows := make([]TaskRow, 0, len(sorted))
	for _, t := range sorted {
		rows = append(rows, TaskRow{
			ID:        t.ID,
			CreatedAt: time.UnixMilli(int64(t.CreatedAt * 1e3)).Format("01-02 15:04:05"),
			Target:    t.Target,
			Module:    moduleLabel(t.Cmd),
			Status:    StatusText(t.Status),
			StatusRaw: t.Status,
		})
	}
	return rows
}

// ResultRow 单个任务的过程/结果表一行。
type ResultRow struct {
	Time   string
	Module string
	Event  string
	Detail string
}

// PageSize 结果页两处长表的每页行数（与 desktop-go 前端同规格：50 行/页）。
const PageSize = 50

// PageBounds 把 (总行数, 页码, 每页行数) 归一成切片边界。页码越界钳到
// 末页、下限钳到 1；空表返回 (0,0,0)。start/end 为左闭右开下标。
func PageBounds(total, page, size int) (start, end, pages int) {
	if total <= 0 || size <= 0 {
		return 0, 0, 0
	}
	pages = (total + size - 1) / size
	if page < 1 {
		page = 1
	}
	if page > pages {
		page = pages
	}
	start = (page - 1) * size
	end = start + size
	if end > total {
		end = total
	}
	return start, end, pages
}

// FilterTasksByModule 模块 tab 筛选：空串返回原序全量。
func FilterTasksByModule(tasks []store.Task, module string) []store.Task {
	if module == "" {
		return tasks
	}
	out := make([]store.Task, 0, len(tasks))
	for _, t := range tasks {
		if t.Cmd == module {
			out = append(out, t)
		}
	}
	return out
}

// ResultRows 把任务的进度事件转成表格行（时间只显示时分秒）。
func ResultRows(t store.Task) []ResultRow {
	rows := make([]ResultRow, 0, len(t.Progress))
	for _, ev := range t.Progress {
		rows = append(rows, ResultRow{
			Time:   time.UnixMilli(int64(ev.Ts * 1e3)).Format("15:04:05"),
			Module: moduleLabel(ev.Module),
			Event:  ev.Event,
			Detail: ev.Detail,
		})
	}
	return rows
}

// statCounts 仪表盘统计：总数 / 运行中 / 已完成 / 失败。
func statCounts(tasks []store.Task) (total, running, done, failed int) {
	for _, t := range tasks {
		switch t.Status {
		case store.StatusRunning:
			running++
		case store.StatusDone:
			done++
		case store.StatusFail:
			failed++
		}
		total++
	}
	return
}

// fmtSeconds 把时间戳转成日程用短串；0 值返回空。
func fmtSeconds(ts float64) string {
	if ts <= 0 {
		return ""
	}
	return time.UnixMilli(int64(ts * 1e3)).Format("01-02 15:04:05")
}
