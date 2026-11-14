package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) GetPclMcDir(pclExePath string) (string, error) {
	pclExePath = strings.TrimSpace(pclExePath)
	if pclExePath == "" {
		return "", fmt.Errorf("请先选择 PCL 可执行文件")
	}
	if _, err := os.Stat(pclExePath); err != nil {
		return "", fmt.Errorf("PCL 可执行文件不存在: %s", pclExePath)
	}

	setupPath := filepath.Join(filepath.Dir(pclExePath), "PCL", "Setup.ini")
	data, err := os.ReadFile(setupPath)
	if err != nil {
		return "", fmt.Errorf("未找到 PCL 配置文件（PCL\\Setup.ini），请确认选择的是 PCL 启动器")
	}

	// 解析 key:value 行
	mcDir := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "LaunchFolderSelect" && value != "" {
			mcDir = value
		}
	}

	if mcDir == "" {
		return "", fmt.Errorf("PCL 配置中没有设置游戏目录（LaunchFolderSelect）")
	}

	// 校验目录存在
	if info, err := os.Stat(mcDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("PCL 的游戏目录不存在: %s", mcDir)
	}

	return mcDir, nil
}

// MigrateMinecraftDir 迁移 .minecraft 目录
// mode = "full"：完整迁移，复制整个 .minecraft 到 QGL 目录（独立副本，PCL 出问题不影响 QGL）
// mode = "minimal"：最小迁移，仅把 QGL 的游戏目录指向 PCL 的 .minecraft（共用，PCL 出问题 QGL 一起出问题）
// 返回迁移后的实际游戏目录
