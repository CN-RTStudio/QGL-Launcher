package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ===== 加载器安装 =====

func (a *App) extractForgeInstaller() (string, error) {
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	cacheDir := filepath.Join(tempDir, "qgl_cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %v", err)
	}

	installerPath := filepath.Join(cacheDir, "forge_installer.jar")

	if state := inspectRegularFile(installerPath); state.trustable() && state.Size == int64(len(forgeInstallerJar)) {
		return installerPath, nil
	}

	// 安装器 jar 走原子私有写：避免进程在落盘途中崩溃留下半截 jar，并拒绝沿既有
	// 符号链接把安装器写到缓存目录外。
	if err := secureWritePrivateFile(installerPath, forgeInstallerJar); err != nil {
		return "", fmt.Errorf("提取 ForgeInstaller 失败: %w", err)
	}

	return installerPath, nil
}

func isOldForge(versionStr string) bool {
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1]
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}
