package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）

func (a *App) findNewVersionFolder(mcDir string, oldVersions map[string]bool, mcVersion string, loaderType string) string {
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	// 优先查找新增的文件夹
	for _, entry := range entries {
		if !entry.IsDir() || oldVersions[entry.Name()] {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		// 检查是否包含加载器类型和 MC 版本
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	// 如果没有找到新增的，查找所有匹配的文件夹
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	return ""
}

// InstallFabric 安装 Fabric（直接下载 profile JSON + 预下载库文件）
func (a *App) InstallFabric(mcVersion string, loaderVersion string) error {
	mcDir := a.GetMinecraftDir()

	// Fabric 阶段划分：profile 获取 + JSON 写入 0-15%，库文件 15-95%，验证 95-100%
	a.setProgressScale(0, 15)

	// 1. 获取 Fabric profile JSON（BMCLAPI 镜像）
	profileURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/fabric-meta/v2/versions/loader/%s/%s/profile/json",
		mcVersion, loaderVersion,
	)

	a.emitProgress("downloading", "获取 Fabric profile", 0, 0)

	resp, err := http.Get(profileURL)
	if err != nil {
		return fmt.Errorf("获取 Fabric profile 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 Fabric profile 失败: HTTP %d", resp.StatusCode)
	}

	var profileJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&profileJSON); err != nil {
		return fmt.Errorf("解析 Fabric profile 失败: %v", err)
	}

	// 2. 设置版本 ID
	versionID := fmt.Sprintf("fabric-loader-%s-%s", loaderVersion, mcVersion)
	profileJSON["id"] = versionID

	// 3. 创建版本文件夹
	versionDir := filepath.Join(mcDir, "versions", versionID)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	// 4. 保存版本 JSON
	jsonData, err := json.MarshalIndent(profileJSON, "", "  ")
	if err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("序列化 JSON 失败: %v", err)
	}

	jsonPath := filepath.Join(versionDir, versionID+".json")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("保存版本 JSON 失败: %v", err)
	}

	// Fabric 阶段划分：profile 获取 + JSON 写入 0-15%，库文件 15-95%，验证 95-100%
	a.setProgressScale(15, 95)
	a.emitProgress("downloading", "下载 Fabric 库文件", 0, 0)
	a.downloadFabricLibraries(profileJSON, mcDir)
	a.setProgressScale(95, 100)

	// 6. 验证安装
	if !a.validateVersionInstallation(versionDir) {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("Fabric 安装验证失败")
	}

	return nil
}

// downloadFabricLibraries 下载 Fabric 版本 JSON 中引用的所有库文件
func (a *App) downloadFabricLibraries(profileJSON map[string]interface{}, mcDir string) {
	libsDir := filepath.Join(mcDir, "libraries")

	// 从 profileJSON 的 libraries 数组中提取需要下载的库
	libs, ok := profileJSON["libraries"].([]interface{})
	if !ok {
		fmt.Printf("Fabric profile JSON 中没有 libraries 字段\n")
		return
	}

	downloadedCount := 0
	// 先收集需要下载的库，再带计数进度下载
	type fabLibTask struct {
		url  string
		path string
	}
	var fabTasks []fabLibTask
	for _, libRaw := range libs {
		libMap, ok := libRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// 获取 downloads.artifact 信息
		downloads, ok := libMap["downloads"].(map[string]interface{})
		if !ok {
			continue
		}

		artifact, ok := downloads["artifact"].(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := artifact["url"].(string)
		path, _ := artifact["path"].(string)
		if url == "" || path == "" {
			continue
		}

		// 替换为 BMCLAPI 镜像（覆盖所有已知的 Maven 仓库）
		url = strings.Replace(url, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1)

		destPath := filepath.Join(libsDir, path)

		// 已存在则跳过
		if _, err := os.Stat(destPath); err == nil {
			continue
		}

		fabTasks = append(fabTasks, fabLibTask{url: url, path: destPath})
	}

	for i, task := range fabTasks {
		a.emitProgress("downloading", fmt.Sprintf("Fabric 库文件 %d/%d", i+1, len(fabTasks)), int64(i+1), int64(len(fabTasks)))
		os.MkdirAll(filepath.Dir(task.path), 0755)
		if err := a.downloadFile(task.url, task.path, false); err != nil {
			fmt.Printf("下载 Fabric 库失败: %v\n", err)
		} else {
			downloadedCount++
		}
	}

	if downloadedCount > 0 {
		fmt.Printf("Fabric 库文件预下载完成: 成功下载 %d 个\n", downloadedCount)
	}
}

// InstallNeoForge 安装 NeoForge（使用 bangbang93 ForgeInstaller）
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
