package main

import (
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) GetInstalledVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}

	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		// 验证版本是否完整安装
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}

		info := a.readVersionInfo(versionFolder, entry.Name())
		installed = append(installed, info)
	}

	return installed, nil
}

// ScanVersions 扫描所有版本文件夹，创建/更新 QGL/config.json，返回最新列表
