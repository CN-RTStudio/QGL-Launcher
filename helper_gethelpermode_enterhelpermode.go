package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) EnterHelperMode(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("路径不能为空")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("路径不存在: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("路径不是文件夹: %s", dir)
	}
	// 如果选择的不是 .minecraft 本身而是包含 .minecraft 的目录，自动进入 .minecraft
	mcPath := filepath.Join(dir, ".minecraft")
	if strings.ToLower(filepath.Base(dir)) != ".minecraft" {
		if _, err := os.Stat(mcPath); err == nil {
			dir = mcPath
		}
	}

	config, err := a.GetGlobalConfig()
	if err != nil {
		return err
	}
	config.HelperMode = true
	config.HelperModeDir = dir
	return a.SaveGlobalConfig(config)
}

// ExitHelperMode 退出辅助模式
