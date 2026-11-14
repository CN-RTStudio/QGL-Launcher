package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (a *App) ScanVersions() ([]InstalledVersionInfo, error) {
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
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}
		info := a.scanVersionFolder(versionFolder, entry.Name())
		installed = append(installed, info)
	}
	return installed, nil
}

// readQGLVersionConfig 有界读取某个版本目录下启动器自写的 QGL/config.json。
// 历史上 readVersionInfo / scanVersionFolder 各自 os.ReadFile+Unmarshal 一份，
// 既重复又没有体积上限；统一收口到 readLocalJSONBounded。
func readQGLVersionConfig(versionFolder string) (map[string]string, bool) {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	var config map[string]string
	if err := readLocalJSONBounded(configPath, &config, 0, "版本 QGL 配置"); err != nil {
		return nil, false
	}
	return config, true
}
