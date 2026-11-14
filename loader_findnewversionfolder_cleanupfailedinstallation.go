package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) cleanupFailedInstallation(mcDir string, versionID string) {
	versionFolder := filepath.Join(mcDir, "versions", versionID)

	// 删除版本文件夹
	if _, err := os.Stat(versionFolder); err == nil {
		os.RemoveAll(versionFolder)
	}

	// 删除临时安装器文件
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// 清理 Forge installer
	forgeInstaller := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", versionID))
	if _, err := os.Stat(forgeInstaller); err == nil {
		os.Remove(forgeInstaller)
	}

	// 清理 NeoForge installer
	neoForgeInstaller := filepath.Join(tempDir, fmt.Sprintf("neoforge-%s-installer.jar", versionID))
	if _, err := os.Stat(neoForgeInstaller); err == nil {
		os.Remove(neoForgeInstaller)
	}

	// 清理 OptiFine installer
	optifineInstaller := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s*.jar", versionID))
	matches, _ := filepath.Glob(optifineInstaller)
	for _, m := range matches {
		os.Remove(m)
	}
}

// CheckLoaderInstalled 检查加载器是否已安装
func (a *App) CheckLoaderInstalled(mcVersion string, loaderName string) bool {
	mcDir := a.GetMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		switch loaderName {
		case "forge":
			if strings.Contains(name, "forge") && !strings.Contains(name, "neo") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "fabric":
			if strings.Contains(name, "fabric") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "neoforge":
			if (strings.Contains(name, "neoforge") || (strings.Contains(name, "forge") && strings.Contains(name, "1.20.1"))) && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		case "optifine":
			if strings.Contains(name, "optifine") && strings.Contains(name, strings.ToLower(mcVersion)) {
				versionFolder := filepath.Join(versionsDir, entry.Name())
				return a.validateVersionInstallation(versionFolder)
			}
		}
	}

	return false
}

// AddLoaderToDownloadList 添加加载器安装器到下载列表（已废弃，改用 game+loader 类型）
func (a *App) AddLoaderToDownloadList(loaderName string, mcVersion string, loaderVersion string, downloadURL string) error {
	customName := fmt.Sprintf("%s %s (%s)", loaderName, loaderVersion, mcVersion)

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         fmt.Sprintf("loader-%s-%s", loaderName, loaderVersion),
		URL:        downloadURL,
		CustomName: customName,
		Type:       "loader",
		ItemType:   "loader",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// downloadLoaderItem 下载加载器安装器（已废弃）
func (a *App) downloadLoaderItem(item *DownloadItem) error {
	if item.URL == "" {
		return fmt.Errorf("下载地址为空")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	fileName := item.CustomName
	if strings.HasSuffix(strings.ToLower(item.URL), ".jar") {
		if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
			fileName += ".jar"
		}
	} else if strings.HasSuffix(strings.ToLower(item.URL), ".exe") {
		if !strings.HasSuffix(strings.ToLower(fileName), ".exe") {
			fileName += ".exe"
		}
	}

	destPath := filepath.Join(tempDir, fileName)

	a.emitProgress("downloading", fileName, 0, 0)

	if err := a.downloadFile(item.URL, destPath, true); err != nil {
		return fmt.Errorf("下载加载器失败: %v", err)
	}

	// 如果是 JAR 安装器，自动运行
	if strings.HasSuffix(strings.ToLower(destPath), ".jar") {
		javaEntry := a.SearchJava()
		if len(javaEntry) == 0 {
			return fmt.Errorf("下载完成但未找到 Java 来运行安装器，请手动运行: %s", destPath)
		}
		cmd := exec.Command(javaEntry[0].Path, "-jar", destPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动安装器失败: %v", err)
		}
	}

	return nil
}
