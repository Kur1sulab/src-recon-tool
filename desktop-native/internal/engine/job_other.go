//go:build !windows

package engine

import "io"

// attachJob 非 Windows 平台无 Job Object 语义，返回 nil Closer——
// 进程树终止沿用 killTree 路径。
func attachJob(pid int) (io.Closer, error) {
	return nil, nil
}
