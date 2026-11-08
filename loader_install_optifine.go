package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func (a *App) InstallOptiFine(mcVersion string, optifineType string, optifinePatch string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(optifineType) || !isSafeFileName(optifinePatch) {
		return fmt.Errorf("无效的 OptiFine 版本格式")
	}

	mcDir := a.GetMinecraftDir()

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	installerPath := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s_%s_%s.jar", mcVersion, optifineType, optifinePatch))

	a.emitProgress("downloading", "下载 OptiFine", 0, 0)

	downloadURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
		mcVersion, optifineType, optifinePatch,
	)

	os.Remove(installerPath)

	if err := a.downloadFile(downloadURL, installerPath, true); err != nil {
		return fmt.Errorf("下载 OptiFine 失败: %v", err)
	}

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}

	a.ensureLauncherProfiles(mcDir)

	oldVersions := a.getVersionFolderList(mcDir)

	a.emitProgress("downloading", "运行 OptiFine 安装器", 0, 0)

	mcDirParent := filepath.Dir(mcDir)

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, fmt.Sprintf("-Duser.home=%s", mcDirParent), "-cp", installerPath, "optifine.Installer")

	// 启动前审计 OptiFine 安装器 JVM：安装 jar 必须位于 mcDir 或其自身所在目录之内，
	// 阻止被 mcVersion/optifineType 等清单字段间接带到 UNC / 穿越 / 目录之外的 jar。
	ofAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{installerPath},
		MainClass:    "optifine.Installer",
		AllowedRoots: []string{mcDir, filepath.Dir(installerPath)},
	})
	if ofAudit.HasCritical() {
		return fmt.Errorf("OptiFine 安装器启动审计未通过: %s", ofAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// OptiFine 安装器同样是独立 JVM：净化环境并剥离隐式 JVM 参数变量，
	// APPDATA 仍按原需求指向 mcDir 的父目录（以 extra 覆盖方式安全注入）。
	a.applySanitizedJVMEnv(cmd, "OptiFineInstaller", map[string]string{
		"APPDATA": mcDirParent,
	})

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("安装 OptiFine 失败: %v\n输出: %s", err, string(output))
	}

	newVersionFolder := a.findNewVersionFolder(mcDir, oldVersions, mcVersion, "optifine")
	if newVersionFolder == "" {
		return fmt.Errorf("OptiFine 安装器运行完成但未找到版本文件夹")
	}

	if !a.validateVersionInstallation(newVersionFolder) {
		os.RemoveAll(newVersionFolder)
		return fmt.Errorf("OptiFine 安装验证失败：版本 JSON 无效")
	}

	fmt.Printf("OptiFine 安装成功: %s\n", filepath.Base(newVersionFolder))

	os.Remove(installerPath)

	return nil
}

// ===== 辅助函数 =====

func (a *App) validateVersionInstallation(versionFolder string) bool {
	if _, err := os.Stat(versionFolder); os.IsNotExist(err) {
		return false
	}

	jsonFiles, err := filepath.Glob(filepath.Join(versionFolder, "*.json"))
	if err != nil || len(jsonFiles) == 0 {
		return false
	}

	for _, jsonFile := range jsonFiles {
		var jsonData map[string]interface{}
		if err := readLocalJSONBounded(jsonFile, &jsonData, 0, "版本 JSON"); err != nil {
			continue
		}

		if jsonData["id"] == nil || jsonData["mainClass"] == nil {
			continue
		}

		return true
	}

	return false
}
