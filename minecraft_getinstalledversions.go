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

// InstalledVersionInfo 安装版本的信息
type InstalledVersionInfo struct {
	FolderName string `json:"folderName"` // 文件夹名（用于启动）
	Name       string `json:"name"`       // 显示名（可能为空）
	Version    string `json:"version"`    // 游戏版本（如 1.12.2）
	Loader     string `json:"loader"`     // 加载器（forge/fabric/neoforge，可能为空）
	Type       string `json:"type"`       // 类型：game/loader/modpack
}

// readVersionInfo 仅读取 QGL/config.json，没有则返回基本信息（不创建）
