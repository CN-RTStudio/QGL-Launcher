package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

)

func (a *App) InstallNeoForge(mcVersion string, neoForgeVersion string) error {
	// neoForgeVersion 可能是 "47.1.99" 或 "1.20.1-47.1.99"
	apiName := neoForgeVersion
	if !strings.Contains(neoForgeVersion, mcVersion+"-") && mcVersion == "1.20.1" {
		apiName = mcVersion + "-" + neoForgeVersion
	}

	mcDir := a.GetMinecraftDir()

	// 确定包名
	pkgName := "neoforge"
	if mcVersion == "1.20.1" {
		pkgName = "forge"
	}

	// 1. 下载 NeoForge installer
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// NeoForge 阶段划分：安装器下载 0-30%，支持库 35-90%，运行安装器 90-100%
	a.setProgressScale(0, 30)

	installerPath := filepath.Join(tempDir, fmt.Sprintf("neoforge-%s-installer.jar", apiName))

	a.emitProgress("downloading", "下载 NeoForge 安装器", 0, 0)

	// BMCLAPI 镜像下载
	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/maven/net/neoforged/%s/%s/%s-%s-installer.jar",
		pkgName, apiName, pkgName, apiName,
	)

	// 删除旧的安装器文件
	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		return fmt.Errorf("下载 NeoForge 安装器失败: %v", err)
	}

	// 2. 分析并下载支持库
	a.setProgressScale(35, 90)
	a.emitProgress("downloading", "分析 NeoForge 支持库", 0, 0)
	if err := a.downloadForgeLibraries(installerPath, mcDir, mcVersion); err != nil {
		fmt.Printf("下载 NeoForge 支持库失败（将继续尝试安装）: %v\n", err)
	}

	// 3. 确保 launcher_profiles.json 存在
	a.ensureLauncherProfiles(mcDir)

	// 4. 记录当前版本文件夹列表
	oldVersions := a.getVersionFolderList(mcDir)

	// 5. 运行 bangbang93 ForgeInstaller
	a.setProgressScale(90, 100)
	a.emitProgress("downloading", "运行 NeoForge 安装器", 0, 0)

	err := a.runForgeInstaller(installerPath, mcDir)
	if err != nil {
		return err
	}

	// 6. 查找安装器创建的版本文件夹
	loaderType := "neoforge"
	if mcVersion == "1.20.1" {
		loaderType = "forge" // 1.20.1 的 NeoForge 版本文件夹名包含 "forge"
	}
	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, loaderType)
	if newVersionFolder == "" {
		return fmt.Errorf("NeoForge 安装器运行完成但未找到版本文件夹")
	}

	// 7. 验证安装
	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("NeoForge 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("NeoForge 安装成功: %s\n", filepath.Base(newVersionFolder))

	// 8. 清理安装器
	os.Remove(installerPath)

	return nil
}

// InstallOptiFine 安装 OptiFine（按照 PCL 的方式运行安装器）
func (a *App) InstallOptiFine(mcVersion string, optifineType string, optifinePatch string) error {
	mcDir := a.GetMinecraftDir()

	// 1. 下载 OptiFine jar
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// OptiFine 阶段划分：下载 0-60%，运行安装器 60-95%，验证 95-100%
	a.setProgressScale(0, 60)

	installerPath := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s_%s_%s.jar", mcVersion, optifineType, optifinePatch))

	a.emitProgress("downloading", "下载 OptiFine", 0, 0)

	// BMCLAPI 镜像下载
	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
		mcVersion, optifineType, optifinePatch,
	)

	// 删除旧的安装器文件
	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		return fmt.Errorf("下载 OptiFine 失败: %v", err)
	}

	// 2. 选择 Java
	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}

	// 3. 确保 launcher_profiles.json 存在
	a.ensureLauncherProfiles(mcDir)

	// 4. 记录当前版本文件夹列表
	oldVersions := a.getVersionFolderList(mcDir)

	// 5. 运行 OptiFine 安装器（按照 PCL 的方式）
	a.setProgressScale(60, 95)
	a.emitProgress("downloading", "运行 OptiFine 安装器", 0, 0)

	// PCL: -Duser.home="{BaseMcFolderHome去尾斜杠}" -cp "{Target}" optifine.Installer
	// 设置 appdata 环境变量指向 .minecraft 的父目录
	mcDirParent := filepath.Dir(mcDir)

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, fmt.Sprintf("-Duser.home=%s", mcDirParent), "-cp", installerPath, "optifine.Installer")

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// 设置 appdata 环境变量
	cmd.Env = append(os.Environ(), fmt.Sprintf("APPDATA=%s", mcDirParent))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("安装 OptiFine 失败: %v\n输出: %s", err, string(output))
	}

	// 6. 查找安装器创建的版本文件夹
	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "optifine")
	if newVersionFolder == "" {
		return fmt.Errorf("OptiFine 安装器运行完成但未找到版本文件夹")
	}

	// 7. 验证安装
	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("OptiFine 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("OptiFine 安装成功: %s\n", filepath.Base(newVersionFolder))

	// 8. 清理安装器
	os.Remove(installerPath)

	return nil
}

// ===== 辅助函数 =====

// validateVersionInstallation 验证版本是否安装成功
func (a *App) validateVersionInstallation(versionFolder string) bool {
	// 检查版本文件夹是否存在
	if _, err := os.Stat(versionFolder); os.IsNotExist(err) {
		return false
	}

	// 检查版本 JSON 文件是否存在
	jsonFiles, err := filepath.Glob(filepath.Join(versionFolder, "*.json"))
	if err != nil || len(jsonFiles) == 0 {
		return false
	}

	// 检查 JSON 文件是否有效
	for _, jsonFile := range jsonFiles {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			continue
		}

		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			continue
		}

		// 检查必要字段
		if jsonData["id"] == nil || jsonData["mainClass"] == nil {
			continue
		}

		// JSON 有效
		return true
	}

	return false
}

// cleanupFailedInstallation 清理安装失败的版本
