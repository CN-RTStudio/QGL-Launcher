package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) InstallForge(mcVersion string, forgeVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(forgeVersion) {
		return fmt.Errorf("无效的 Forge 版本格式")
	}

	a.writeLog("========== 开始安装 Forge: MC=%s, Forge=%s ==========", mcVersion, forgeVersion)

	fullVersion := forgeVersion
	if !strings.Contains(forgeVersion, mcVersion) {
		fullVersion = mcVersion + "-" + forgeVersion
	}
	a.writeLog("完整版本号: %s", fullVersion)

	mcDir := a.GetMinecraftDir()
	a.writeLog(".minecraft 目录: %s", mcDir)

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", fullVersion))

	a.emitProgress("downloading", "下载 Forge 安装器", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-installer.jar",
		fullVersion, fullVersion,
	)
	a.writeLog("下载 URL: %s", downloadURL)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		a.writeLog("下载 Forge 安装器失败: %v", err)
		return fmt.Errorf("下载 Forge 安装器失败: %v", err)
	}

	if info, err := os.Stat(installerPath); err == nil {
		a.writeLog("安装器文件大小: %d 字节", info.Size())
	}

	isOld := isOldForge(fullVersion)
	a.writeLog("是否为旧版 Forge (<20): %v", isOld)

	if isOld {
		a.emitProgress("downloading", "安装旧版 Forge", 0, 0)
		return a.installOldForge(installerPath, mcDir, mcVersion)
	}

	a.emitProgress("downloading", "分析 Forge 支持库", 0, 0)

	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		a.writeLog("下载 Forge 支持库失败（将继续尝试安装）: %v", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 Forge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "forge")
	if newVersionFolder == "" {
		return fmt.Errorf("Forge 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("Forge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("Forge 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}
