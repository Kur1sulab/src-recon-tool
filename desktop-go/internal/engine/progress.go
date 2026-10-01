package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"os"

	"recon-desktop/internal/store"
)

// Tailer 增量读取进度 JSONL：记录已消费偏移，每次 Poll 只吐新事件；
// 半行（进程正写到一半）缓存在 pending，等下次补全，绝不丢事件。
type Tailer struct {
	path    string
	offset  int64
	pending []byte
}

// NewTailer 建立游标。文件尚不存在时 Poll 返回空（进程还没写第一行）。
func NewTailer(path string) *Tailer {
	return &Tailer{path: path}
}

// Poll 读取自上次以来的新事件。读不到文件/读失败一律返回空切片——
// 进度落盘失败不该拖垮扫描任务本身。
func (t *Tailer) Poll() []store.ProgressEvent {
	f, err := os.Open(t.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(f)
	if err != nil || len(data) == 0 {
		return nil
	}
	buf := append(t.pending, data...)
	var evs []store.ProgressEvent
	consumed := 0
	for {
		i := bytes.IndexByte(buf[consumed:], '\n')
		if i < 0 {
			break
		}
		line := buf[consumed : consumed+i]
		consumed += i + 1
		if ev, ok := ParseLine(line); ok {
			evs = append(evs, ev)
		}
	}
	t.pending = append(t.pending[:0], buf[consumed:]...)
	// 偏移推进到文件已读到的末尾：半行字节由 pending 持有，
	// 否则下次 Poll 会重读同一段造成事件重复。
	t.offset += int64(len(data))
	return evs
}

// ParseLine 解析一行 JSONL 事件；坏行一律跳过。
func ParseLine(b []byte) (store.ProgressEvent, bool) {
	var ev store.ProgressEvent
	if err := json.Unmarshal(bytes.TrimSpace(b), &ev); err != nil {
		return store.ProgressEvent{}, false
	}
	if ev.Event == "" || ev.Module == "" {
		return store.ProgressEvent{}, false
	}
	return ev, true
}

// HasPipelineEnd 判断事件流里是否已出现 pipeline_end（进程收尾标志）。
func HasPipelineEnd(evs []store.ProgressEvent) bool {
	for _, ev := range evs {
		if ev.Event == "pipeline_end" {
			return true
		}
	}
	return false
}
