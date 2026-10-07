package cli

// 进度事件 JSONL 落盘——契约对齐 recon.py:31-62（桌面壳 desktop-go 的
// Runner/monitor 靠这套事件驱动任务状态机，fix1 审计 medium#4 补齐 Go 侧缺口）：
//   - 全局参数 --progress-file <path> / --progress-file=<path>，必须出现在子命令之前
//     （argparse 主解析器参数，recon.py:161-163）；CLI 参数优先于环境变量
//     RECON_PROGRESS_FILE（recon.py:190-191）；
//   - 事件一行一条 JSON，键恰为 {ts,event,module,detail}，ts 秒级浮点 3 位小数
//     （与 desktop-go/internal/store.ProgressEvent 的解析契约一致）；
//   - 事件序对齐 recon.py:195-257：
//       pipeline_start(pipeline,cmd) → [start(cmd)] → [done|fail(cmd,detail)] → pipeline_end(pipeline,done|fail)
//     cmd=="all" 时不发模块级 start/done|fail（recon.py:196-197、250-256 的豁免分支）；
//     无子命令 / help 不发任何事件（argparse 阶段即退出）。
//   - 任何落盘失败静默吞掉，绝不影响扫描主流程（_emit 语义）。

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// progressFile 当前进度 JSONL 落盘路径（空 = 关闭），语义等价 recon._PROGRESS_FILE。
var progressFile string

// progressRec 事件记录（键序 ts,event,module,detail 与 Python json.dumps 一致）。
type progressRec struct {
	Ts     float64 `json:"ts"`
	Event  string  `json:"event"`
	Module string  `json:"module"`
	Detail string  `json:"detail"`
}

// emit 追加一条进度事件；失败静默（目录不存在/路径非法等一律吞掉）。
func emit(event, module, detail string) {
	if progressFile == "" {
		return
	}
	ts := float64(time.Now().UnixNano()) / 1e9
	rec := progressRec{Ts: math.Round(ts*1e3) / 1e3, Event: event, Module: module, Detail: detail}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(progressFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// applyProgressFile 解析全局 --progress-file 参数（必须在子命令之前），
// 返回去掉全局参数后的剩余 argv。对齐 argparse 行为：
//   - "--progress-file <path>" 与 "--progress-file=<path>" 两种形态均接受；
//   - 其他以 "-" 开头的全局 token 一律拒绝（argparse 对未知全局选项 exit 2）；
//   - 首个非旗标 token 视为子命令，其后内容原样交 dispatch。
func applyProgressFile(args []string) ([]string, int) {
	for len(args) > 0 {
		tok := args[0]
		if !strings.HasPrefix(tok, "-") {
			return args, 0 // 子命令起点
		}
		switch {
		case tok == "--progress-file": // fix3：argparse 不认下划线别名，仅精确长名
			if len(args) < 2 {
				fmt.Println("[!] --progress-file 需要一个路径参数\n\n用法: recon-go [--progress-file <path>] <子命令> ...")
				return nil, 2
			}
			setProgressFile(args[1])
			args = args[2:]
		case strings.HasPrefix(tok, "--progress-file="):
			setProgressFile(strings.TrimPrefix(tok, "--progress-file="))
			args = args[1:]
		case tok == "-h" || tok == "--help" || tok == "help":
			return nil, -1 // 帮助：不发事件，退出码 0
		default:
			fmt.Printf("[!] 未知全局参数: %s\n（全局仅支持 --progress-file；其余参数请放在子命令之后）\n", tok)
			return nil, 2
		}
	}
	fmt.Print(helpText)
	return nil, 1 // 只有全局参数没有子命令：等价 Python 无 cmd 分支（exit 1，不发事件）
}

// setProgressFile CLI 参数优先，其次环境变量 RECON_PROGRESS_FILE（recon.py:191）。
func setProgressFile(p string) {
	if p == "" {
		p = os.Getenv("RECON_PROGRESS_FILE")
	}
	progressFile = p
}
