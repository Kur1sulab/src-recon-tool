package ui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Settings 桌面端设置（settings.json，与任务库同目录）。
// 只存用户显式选择；不存任何凭据类内容。
// 终修轮：PythonPath/GoEnginePath 退役幽灵字段移除——直调重写后引擎内置，
// 无解释器/外部引擎路径可配（该二子进程均已退役）。旧 settings.json 里的
// python_path/go_engine_path 键读入时忽略、下次保存自然排出。
type Settings struct{}

// settingsFile 设置文件名。
const settingsFile = "settings.json"

// LoadSettings 读设置。缺文件/坏文件一律兜底为零值不报错——
// 设置读不出来不该挡住桌面端启动。
func LoadSettings(dataDir string) (Settings, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, settingsFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Settings{}, nil
		}
		return Settings{}, err
	}
	var st Settings
	if err := json.Unmarshal(data, &st); err != nil {
		return Settings{}, nil // 坏文件 → 零值
	}
	return st, nil
}

// SaveSettings 原子写设置（临时文件 + rename）。
func SaveSettings(dataDir string, st Settings) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(dataDir, settingsFile)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
