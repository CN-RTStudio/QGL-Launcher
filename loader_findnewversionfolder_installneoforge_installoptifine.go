package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

)

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
