package main

// Windows 桌面壳配套：窗口尺寸记忆（window.json）、单实例互斥、原生消息框、
// 窗口矩形采样（user32）。非 Windows 平台回退为无壳运行（--dev）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// windowState 记住的窗口大小。
type windowState struct {
	W uint `json:"w"`
	H uint `json:"h"`
}

func clampSize(w, h uint) (uint, uint) {
	if w < 960 {
		w = 960
	}
	if h < 640 {
		h = 640
	}
	if w > 7680 {
		w = 7680
	}
	if h > 4320 {
		h = 4320
	}
	return w, h
}

// loadWindow 读回窗口尺寸；文件缺失/损坏一律回默认 1280x800。
func loadWindow(dataDir string) windowState {
	def := windowState{W: 1280, H: 800}
	data, err := os.ReadFile(filepath.Join(dataDir, "window.json"))
	if err != nil {
		return def
	}
	var st windowState
	if err := json.Unmarshal(data, &st); err != nil {
		return def
	}
	st.W, st.H = clampSize(st.W, st.H)
	return st
}

// saveWindow 退出前落盘窗口尺寸。
func saveWindow(dataDir string, w, h uint) {
	w, h = clampSize(w, h)
	data, err := json.Marshal(windowState{W: w, H: h})
	if err != nil {
		return
	}
	p := filepath.Join(dataDir, "window.json")
	_ = os.MkdirAll(dataDir, 0o755)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

// dataDirPath 数据目录：%LOCALAPPDATA%/recon-desktop（无该环境变量时退 UserConfigDir）。
func dataDirPath() string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "recon-desktop")
	}
	if base, err := os.UserConfigDir(); err == nil {
		return filepath.Join(base, "recon-desktop")
	}
	return ".recon-desktop"
}

// ── user32 / kernel32 ──

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetWindowRect = user32.NewProc("GetWindowRect")
	procMessageBoxW   = user32.NewProc("MessageBoxW")
	procCreateMutexW  = kernel32.NewProc("CreateMutexW")
)

type rect struct {
	Left, Top, Right, Bottom int32
}

// windowSize 采样窗口当前客户区外框大小（用于尺寸记忆）。
func windowSize(hwnd unsafe.Pointer) (uint, uint, bool) {
	if hwnd == nil {
		return 0, 0, false
	}
	var r rect
	r1, _, _ := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&r)))
	if r1 == 0 {
		return 0, 0, false
	}
	w, h := r.Right-r.Left, r.Bottom-r.Top
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return uint(w), uint(h), true
}

// acquireSingleInstance 命名互斥量防重复开壳。创建互斥量本身失败时放行（不因小沙误伤可用性）。
func acquireSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(`Local\recon-desktop-singleton`)
	if err != nil {
		return true
	}
	const errorAlreadyExists = 183
	handle, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return true
	}
	errno, _ := callErr.(syscall.Errno)
	return errno != errorAlreadyExists
}

// messageBox 原生弹窗（壳模式下无控制台可写）。
func messageBox(text string) {
	utf16Text, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	utf16Title, _ := syscall.UTF16PtrFromString("侦察工作台")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16Text)), uintptr(unsafe.Pointer(utf16Title)), 0x40) // MB_ICONINFORMATION
}
