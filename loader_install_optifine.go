package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	installerState := inspectRegularFile(installerPath)
	if !installerState.trustable() {
		return fmt.Errorf("OptiFine 安装器不是可信任的普通文件: %s", describeUntrustedFile(installerState, installerPath))
	}

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
	info, err := os.Lstat(versionFolder)
	if err != nil || !info.IsDir() {
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

func (a *App) cleanupFailedInstallation(mcDir string, versionID string) {
	versionFolder := filepath.Join(mcDir, "versions", versionID)

	if info, err := os.Lstat(versionFolder); err == nil && info.IsDir() {
		os.RemoveAll(versionFolder)
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	forgeInstaller := filepath.Join(tempDir, fmt.Sprintf("forge-%s-installer.jar", versionID))
	if _, err := os.Stat(forgeInstaller); err == nil {
		os.Remove(forgeInstaller)
	}

	neoForgeInstaller := filepath.Join(tempDir, fmt.Sprintf("neoforge-%s-installer.jar", versionID))
	if _, err := os.Stat(neoForgeInstaller); err == nil {
		os.Remove(neoForgeInstaller)
	}

	optifineInstaller := filepath.Join(tempDir, fmt.Sprintf("OptiFine_%s*.jar", versionID))
	matches, _ := filepath.Glob(optifineInstaller)
	for _, m := range matches {
		os.Remove(m)
	}
}

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

func (a *App) AddLoaderToDownloadList(loaderName string, mcVersion string, loaderVersion string, downloadURL string) error {
	// 三个标识全部来自前端，最终拼进下载列表展示名并参与安装分发，必须收敛：
	// loaderName 走固定白名单（它决定后续 switch 分支），mc/loader 版本走严格名单段。
	loaderName = strings.ToLower(strings.TrimSpace(loaderName))
	switch loaderName {
	case "forge", "fabric", "neoforge", "optifine":
	default:
		return fmt.Errorf("不支持的加载器类型: %s", loaderName)
	}
	safeMC, whyM := SafeVersionComponent(mcVersion)
	if whyM != nameRejectNone {
		return fmt.Errorf("Minecraft 版本无效: %s", describeNameReject(whyM))
	}
	mcVersion = safeMC
	safeLV, whyL := SafeLoaderComponent(loaderVersion)
	if whyL != nameRejectNone {
		return fmt.Errorf("加载器版本无效: %s", describeNameReject(whyL))
	}
	loaderVersion = safeLV
	customName := fmt.Sprintf("%s %s (%s)", loaderName, loaderVersion, mcVersion)
	if safeName, why := SafeVersionDisplayName(customName); why != nameRejectNone {
		return fmt.Errorf("加载器任务名称无效: %s", describeNameReject(why))
	} else {
		customName = safeName
	}
	// 下载地址来自前端，最终会"下载即运行"第三方安装器：入队时就先把非 HTTPS
	// 链接挡掉，避免恶意 / 被劫持的明文地址进入队列后才在下载阶段暴露。
	// 空地址交给下载阶段统一报错（个别加载器走内置安装器路径时可能不带 URL）。
	if strings.TrimSpace(downloadURL) != "" && !isHTTPSURL(downloadURL) {
		return fmt.Errorf("不支持的加载器下载地址（仅允许 HTTPS）")
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         fmt.Sprintf("loader-%s-%s", loaderName, loaderVersion),
		URL:        downloadURL,
		CustomName: customName,
		Type:       "loader",
		ItemType:   "loader",
		Status:     "pending",
		Progress:   0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}

	a.downloadList = append(a.downloadList, pending)

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) downloadLoaderItem(item *DownloadItem) error {
	if item.URL == "" {
		return fmt.Errorf("下载地址为空")
	}

	if !isHTTPSURL(item.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// 落盘目标名不再直接取展示名：走 loaderdest 内核，按 URL 路径判定扩展名
	// （忽略 query）、slug 白名单化、追加 UMFS 指纹去碰撞，并断言结果仍严格位于
	// TEMP 内。旧实现 filepath.Base(CustomName) 保留空格 / 括号、文件名可预测，
	// 且 URL 带 ?query 时会漏判 .jar。
	artifactExt := loaderArtifactExt(item.URL)
	destPath, ok := resolveLoaderTempDest(tempDir, item.CustomName, item.URL)
	if !ok {
		return fmt.Errorf("无法在临时目录内构造安全的安装器落盘路径")
	}
	fileName := filepath.Base(destPath)

	a.emitProgress("downloading", fileName, 0, 0)

	if err := a.downloadFile(item.URL, destPath, true); err != nil {
		return fmt.Errorf("下载加载器失败: %v", err)
	}

	if artifactExt == ".jar" {
		javaEntry := a.SearchJava()
		if len(javaEntry) == 0 {
			return fmt.Errorf("下载完成但未找到 Java 来运行安装器，请手动运行: %s", destPath)
		}
		// “下载即运行”的第三方 jar 风险最高：审计目标 jar 必须是 tempDir 内的绝对
		// .jar，阻止 UNC / 穿越 / 目录之外目标，java 可执行同样过绝对/扩展名校验。
		dlAudit := AuditExternalJVM(ExternalJVMPlan{
			JavaExe:      javaEntry[0].Path,
			WorkDir:      tempDir,
			JarAbsPath:   destPath,
			AllowedRoots: []string{tempDir},
		})
		if dlAudit.HasCritical() {
			return fmt.Errorf("下载的安装器启动审计未通过: %s", dlAudit.FirstCriticalCode())
		}
		cmd := exec.Command(javaEntry[0].Path, "-jar", destPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		// 下载下来的第三方 jar 安装器也是独立 JVM，同样不能继承隐式 JVM
		// 参数环境变量，否则下载即运行这条链会被 JAVA_TOOL_OPTIONS 劫持。
		a.applySanitizedJVMEnv(cmd, "DownloadedJarInstaller", nil)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动安装器失败: %v", err)
		}
	}

	return nil
}
