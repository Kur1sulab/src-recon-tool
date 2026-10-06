//go:build windows

package engine

import (
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

// attachJob 把刚起的扫描进程挂进「随壳消亡」的 Job Object：
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE——壳无论优雅退出还是被任务管理器
// 硬杀，Job 句柄随进程回收而关闭，Job 内整树（含 python 起的子进程）
// 同步终局。根治对抗实测 P2：壳被硬杀 → 扫描进程孤儿继续对目标发包
// （独立实验：父进程 taskkill /F 后 PING.EXE 存活且谱系指向已死父链）。
//
// 挂载失败不致命（宿主 Job 限制等），返回 nil Closer——killTree 路径
// 仍是兜底；调用方不因本函数失败而拒绝起扫描。
func attachJob(pid int) (io.Closer, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("进程不可用")
	}
	const (
		procSetQuota  = 0x0100 // AssignProcessToJobObject 所需权限之一
		procTerminate = 0x0001
	)
	ph, err := windows.OpenProcess(procSetQuota|procTerminate, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ph)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	li := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	li.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&li)), uint32(unsafe.Sizeof(li))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	return jobCloser(job), nil
}

// jobCloser Job 句柄。Close 即关闭句柄：KILL_ON_JOB_CLOSE 语义下等于
// 终止 Job 内整树（对已自行退出的进程无害）。
type jobCloser windows.Handle

func (h jobCloser) Close() error {
	return windows.CloseHandle(windows.Handle(h))
}
