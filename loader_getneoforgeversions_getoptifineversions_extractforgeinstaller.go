package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) extractForgeInstaller() (string, error) {
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	cacheDir := filepath.Join(tempDir, "qgl_cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %v", err)
	}

	installerPath := filepath.Join(cacheDir, "forge_installer.jar")

	// 如果已存在且大小正确，直接返回
	if info, err := os.Stat(installerPath); err == nil && info.Size() == int64(len(forgeInstallerJar)) {
		return installerPath, nil
	}

	// 写入文件
	if err := os.WriteFile(installerPath, forgeInstallerJar, 0644); err != nil {
		return "", fmt.Errorf("提取 ForgeInstaller 失败: %v", err)
	}

	return installerPath, nil
}

// isOldForge 判断是否为旧版 Forge（版本号 < 20，不需要运行安装器）
