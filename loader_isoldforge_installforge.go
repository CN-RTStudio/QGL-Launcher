package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) InstallForge(mcVersion string, forgeVersion string) error {
	a.writeLog("========== 开始安装 Forge: MC=%s, Forge=%s ==========", mcVersion, forgeVersion)

	// forgeVersion 可能是 "47.3.0" 或完整版 "1.20.1-47.3.0"
	fullVersion := forgeVersion
	if !strings.Contains(forgeVersion, mcVersion) {
		fullVersion = mcVersion + "-" + forgeVersion
	}
	a.writeLog("完整版本号: %s", fullVersion)

	mcDir := a.GetMinecraftDir()
	a.writeLog(".minecraft 目录: %s", mcDir)

	// 1. 下载 Forge installer
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// Forge 阶段划分：安装器下载 0-30%，支持库 35-90%，运行安装器 90-100%
	a.setProgressScale(0, 30)

	installerPath := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", fullVersion))

	a.emitProgress("downloading", "下载 Forge 安装器", 0, 0)

	// BMCLAPI 镜像下载
	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-installer.jar",
		fullVersion, fullVersion,
	)
	a.writeLog("下载 URL: %s", downloadURL)

	// 删除旧的安装器文件（避免下载跳过损坏文件）
	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		a.writeLog("下载 Forge 安装器失败: %v", err)
		return fmt.Errorf("下载 Forge 安装器失败: %v", err)
	}

	// 检查下载的文件大小
	if info, err := os.Stat(installerPath); err == nil {
		a.writeLog("安装器文件大小: %d 字节", info.Size())
	} else {
		a.writeLog("无法获取安装器文件信息: %v", err)
	}

	// 2. 判断是新版还是旧版
	isOld := isOldForge(fullVersion)
	a.writeLog("是否为旧版 Forge (<20): %v (isOldForge 判断)", isOld)

	if isOld {
		// 旧版 Forge（方式 B）：直接解压 installer jar，不需要运行安装器
		a.setProgressScale(35, 95)
		a.emitProgress("downloading", "安装旧版 Forge", 0, 0)
		return a.installOldForge(installerPath, mcDir, mcVersion)
	}

	// 3. 新版 Forge（方式 A）：先分析支持库，再运行 bangbang93 ForgeInstaller
	a.setProgressScale(35, 90)
	a.emitProgress("downloading", "分析 Forge 支持库", 0, 0)

	// 3.1 解压 installer 获取支持库列表并下载
	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		a.writeLog("下载 Forge 支持库失败（将继续尝试安装）: %v", err)
	}

	// 3.2 确保 launcher_profiles.json 存在
	a.ensureLauncherProfiles(mcDir)

	// 3.3 记录当前版本文件夹列表（在运行安装器之前）
	oldVersions := a.getVersionFolderList(mcDir)

	// 3.4 运行 bangbang93 ForgeInstaller
	a.setProgressScale(90, 100)
	a.emitProgress("downloading", "运行 Forge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	// 3.5 查找安装器创建的版本文件夹
	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "forge")
	if newVersionFolder == "" {
		return fmt.Errorf("Forge 安装器运行完成但未找到版本文件夹")
	}

	// 3.6 验证安装
	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("Forge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("Forge 安装成功: %s\n", filepath.Base(newVersionFolder))

	// 3.7 清理安装器
	os.Remove(installerPath)

	return nil
}

// installOldForge 旧版 Forge 安装（方式 B，不需要运行安装器）
