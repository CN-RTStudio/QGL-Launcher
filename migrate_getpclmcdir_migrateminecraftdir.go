package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) MigrateMinecraftDir(srcDir string, mode string) (string, error) {
	srcDir = strings.TrimSpace(srcDir)
	if srcDir == "" {
		return "", fmt.Errorf("请先选择 .minecraft 文件夹")
	}
	info, err := os.Stat(srcDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("目录不存在: %s", srcDir)
	}

	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}

	var finalDir string
	if mode == "minimal" {
		// 最小迁移：直接指向原目录
		config.MinecraftDir = srcDir
		finalDir = srcDir
	} else {
		// 完整迁移：复制到 QGL 目录
		targetDir := filepath.Join(a.GetQGLDir(), ".minecraft")
		if err := copyDirRecursive(srcDir, targetDir); err != nil {
			return "", fmt.Errorf("复制 .minecraft 失败: %w", err)
		}
		config.MinecraftDir = ""
		finalDir = targetDir
	}

	// 注意：不修改辅助模式状态，辅助模式必须由用户手动进入

	if err := a.SaveGlobalConfig(config); err != nil {
		return "", err
	}
	return finalDir, nil
}

// copyDirRecursive 递归复制目录（已存在则合并覆盖）
