package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ===== 日志功能 =====

// writeLog 将信息写入日志文件（用户可随时查看和复制）
func (a *App) writeLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, msg)

	// 打印到控制台
	fmt.Print(logLine)

	// 写入安装日志（.minecraft 根目录）
	mcDir := a.GetMinecraftDir()
	logPath := filepath.Join(mcDir, "qgl_install.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		f.WriteString(logLine)
		f.Close()
	}

	// 写入启动日志（版本目录下的 QGL\Logs，与 UI 报错内容一致）
	if a.launchLogPath != "" {
		dir := filepath.Dir(a.launchLogPath)
		os.MkdirAll(dir, 0755)
		f2, err2 := os.OpenFile(a.launchLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err2 == nil {
			f2.WriteString(logLine)
			f2.Close()
		}
	}
}

// GetFullLog 获取完整日志文本（优先本次启动日志，其次安装日志）
func (a *App) GetFullLog() string {
	if a.launchLogPath != "" {
		if data, err := os.ReadFile(a.launchLogPath); err == nil && len(data) > 0 {
			return string(data)
		}
	}
	mcDir := a.GetMinecraftDir()
	if data, err := os.ReadFile(filepath.Join(mcDir, "qgl_install.log")); err == nil {
		return string(data)
	}
	return "暂无日志"
}

// ExportLogTxt 弹出保存对话框，将完整日志导出为 txt，返回保存路径（取消返回空）
func (a *App) ExportLogTxt() string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出日志",
		DefaultFilename: "QGL日志.txt",
		Filters: []runtime.FileFilter{
			{DisplayName: "文本文件 (*.txt)", Pattern: "*.txt"},
		},
	})
	if err != nil || path == "" {
		return ""
	}
	if err := os.WriteFile(path, []byte(a.GetFullLog()), 0644); err != nil {
		return ""
	}
	return path
}

// ViewFullLog 用记事本打开完整日志
func (a *App) ViewFullLog() {
	path := a.launchLogPath
	if path == "" {
		path = filepath.Join(a.GetMinecraftDir(), "qgl_install.log")
	}
	// 文件不存在时先写出当前日志内容，保证记事本能打开
	if _, err := os.Stat(path); err != nil {
		os.MkdirAll(filepath.Dir(path), 0755)
		os.WriteFile(path, []byte(a.GetFullLog()), 0644)
	}
	exec.Command("notepad.exe", path).Start()
}

// ===== 嵌入 bangbang93 ForgeInstaller =====

//go:embed resources/forge-installer.jar
var forgeInstallerJar []byte

// ===== 模组加载器相关结构体 =====

// LoaderInfo 模组加载器信息
type LoaderInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Version      string `json:"version"`
	MCVersion    string `json:"mcVersion"`
	DownloadURL  string `json:"downloadUrl"`
	IsInstalled  bool   `json:"isInstalled"`
	Stable       bool   `json:"stable"`
	Category     string `json:"category"`     // installer, universal, client (Forge)
	ForgeVersion string `json:"forgeVersion"` // Forge 完整版本名如 1.20.1-47.3.0
	IsPreview    bool   `json:"isPreview"`    // OptiFine 是否为预览版
	Patch        string `json:"patch"`        // OptiFine patch 版本号
	OptiFineType string `json:"optifineType"` // OptiFine 类型如 HD_U
}

// BMCLAPI Forge 版本条目
type BMCLAPIForgeEntry struct {
	Branch   string `json:"branch"`
	Modified string `json:"modified"`
	Version  string `json:"version"`
	Files    []struct {
		Category string `json:"category"`
		Format   string `json:"format"`
		Hash     string `json:"hash"`
		ID       int    `json:"id"`
		Size     int64  `json:"size"`
	} `json:"files"`
}

// BMCLAPI OptiFine 版本条目
type BMCLAPIOptiFineEntry struct {
	MCVersion string `json:"mcversion"`
	Type      string `json:"type"`
	Patch     string `json:"patch"`
	Filename  string `json:"filename"`
	Forge     string `json:"forge"`
}

// Fabric 加载器版本
type FabricLoaderVersion struct {
	Separator string `json:"separator"`
	Build     int    `json:"build"`
	Version   string `json:"version"`
	Maven     string `json:"maven"`
	Stable    bool   `json:"stable"`
}

// ===== Forge 版本获取（使用 BMCLAPI） =====

// GetForgeVersions 获取 Forge 版本列表
func (a *App) GetForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	apiURL := fmt.Sprintf("https://bmclapi2.bangbang93.com/forge/minecraft/%s", mcVersion)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Forge 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Forge 版本失败: HTTP %d", resp.StatusCode)
	}

	var entries []BMCLAPIForgeEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("解析 Forge 版本失败: %v", err)
	}

	// 获取推荐版本
	recommendedVersion := ""
	promosResp, err := http.Get("https://bmclapi2.bangbang93.com/forge/promos")
	if err == nil && promosResp.StatusCode == http.StatusOK {
		var promos map[string]string
		if json.NewDecoder(promosResp.Body).Decode(&promos) == nil {
			recommendedVersion = promos[mcVersion+"-recommended"]
		}
		promosResp.Body.Close()
	}

	loaders := []LoaderInfo{}
	for _, entry := range entries {
		// 选择最佳文件类型：installer.jar > universal.zip
		var bestFile *struct {
			Category string `json:"category"`
			Format   string `json:"format"`
			Hash     string `json:"hash"`
			ID       int    `json:"id"`
			Size     int64  `json:"size"`
		}

		for i := range entry.Files {
			f := &entry.Files[i]
			if f.Category == "installer" && f.Format == "jar" {
				bestFile = f
				break
			}
			if f.Category == "universal" && bestFile == nil {
				bestFile = f
			}
		}

		if bestFile == nil && len(entry.Files) > 0 {
			bestFile = &entry.Files[0]
		}

		forgeVersion := mcVersion + "-" + entry.Version
		if entry.Branch != "" {
			forgeVersion += "-" + entry.Branch
		}

		category := "installer"
		if bestFile != nil {
			category = bestFile.Category
		}

		// 构建下载 URL
		ext := "jar"
		if category == "universal" || category == "client" {
			ext = "zip"
		}
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/minecraftforge/forge/%s/forge-%s-%s.%s",
			forgeVersion, forgeVersion, category, ext,
		)

		isRecommended := entry.Version == recommendedVersion

		loaders = append(loaders, LoaderInfo{
			Name:         "forge",
			DisplayName:  "Forge",
			Version:      entry.Version,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       isRecommended,
			Category:     category,
			ForgeVersion: forgeVersion,
		})
	}

	return loaders, nil
}

// ===== Fabric 版本获取 =====

// GetFabricVersions 获取 Fabric 版本列表
func (a *App) GetFabricVersions(mcVersion string) ([]LoaderInfo, error) {
	// 参考 PCL：先获取完整版本列表，检查 MC 版本是否在 game 数组中
	// 优先使用 BMCLAPI 镜像，失败回退官方源
	fabricMetaURL := "https://bmclapi2.bangbang93.com/fabric-meta/v2/versions"

	resp, err := http.Get(fabricMetaURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		// 回退到官方源
		resp, err = http.Get("https://meta.fabricmc.net/v2/versions")
		if err != nil {
			return nil, fmt.Errorf("获取 Fabric 版本失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Fabric 版本失败: HTTP %d", resp.StatusCode)
	}

	var fabricMeta struct {
		Game     []struct {
			Version string `json:"version"`
			Stable bool   `json:"stable"`
		} `json:"game"`
		Loader []FabricLoaderVersion `json:"loader"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fabricMeta); err != nil {
		return nil, fmt.Errorf("解析 Fabric 版本失败: %v", err)
	}

	// 检查 MC 版本是否在 game 数组中（参考 PCL LoadFabricGetError）
	mcVersionNormalized := mcVersion
	if mcVersionNormalized == "infinite" {
		mcVersionNormalized = "infinite"
	}
	supported := false
	for _, g := range fabricMeta.Game {
		if g.Version == mcVersionNormalized {
			supported = true
			break
		}
	}
	// 如果不支持，返回空列表（参考 PCL 显示"不可用"）
	if !supported {
		return []LoaderInfo{}, nil
	}

	loaders := []LoaderInfo{}
	for _, lv := range fabricMeta.Loader {
		loaders = append(loaders, LoaderInfo{
			Name:        "fabric",
			DisplayName: "Fabric",
			Version:     lv.Version,
			MCVersion:   mcVersion,
			DownloadURL: "",
			Stable:      lv.Stable,
		})
	}

	return loaders, nil
}

// ===== NeoForge 版本获取 =====

// GetNeoForgeVersions 获取 NeoForge 版本列表（参考 PCL DlNeoForgeList）
func (a *App) GetNeoForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	// NeoForge 仅支持 1.20.1+
	major, minor, patch := parseMCVersion(mcVersion)
	mcNum := major*1000 + minor*100 + patch
	if mcNum < 1201 {
		return []LoaderInfo{}, nil
	}

	// 参考 PCL：同时获取 Legacy 和 Latest 列表
	// Legacy: 1.20.1 (net/neoforged/forge)
	// Latest: 1.20.2+ (net/neoforged/neoforge)
	var allVersions []string

	// 获取 Legacy 列表
	legacyURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/forge"
	if entries, err := fetchNeoForgeVersionList(legacyURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

	// 获取 Latest 列表
	latestURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/neoforge"
	if entries, err := fetchNeoForgeVersionList(latestURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

	// 如果 BMCLAPI 都失败，尝试官方源
	if len(allVersions) == 0 {
		legacyOfficialURL := "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/forge"
		if entries, err := fetchNeoForgeVersionList(legacyOfficialURL); err == nil {
			allVersions = append(allVersions, entries...)
		}
		latestOfficialURL := "https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge"
		if entries, err := fetchNeoForgeVersionList(latestOfficialURL); err == nil {
			allVersions = append(allVersions, entries...)
		}
	}

	loaders := []LoaderInfo{}
	for _, apiName := range allVersions {
		// 参考 PCL DlNeoForgeListEntry.New：根据版本名确定 MC 版本
		isLegacy := strings.Contains(apiName, "1.20.1")
		inheritVersion := ""

		if isLegacy {
			// Legacy: 1.20.1-47.1.99
			inheritVersion = "1.20.1"
		} else {
			// Latest: 20.4.30-beta → MC 1.20.4
			// 参考 PCL：Version = ApiName.BeforeFirst("-")，Inherit = 1.{Major}.{Minor}
			versionPart := apiName
			if idx := strings.Index(apiName, "-"); idx > 0 {
				versionPart = apiName[:idx]
			}
			parts := strings.Split(versionPart, ".")
			if len(parts) >= 2 {
				nfMajor := parts[0] // e.g., "20"
				nfMinor := parts[1]  // e.g., "4"
				// MC 版本 = 1.{nfMajor}.{nfMinor}，如果 nfMinor 为 0 则为 1.{nfMajor}
				if nfMinor == "0" {
					inheritVersion = "1." + nfMajor
				} else {
					inheritVersion = "1." + nfMajor + "." + nfMinor
				}
			}
		}

		// 只保留匹配当前 MC 版本的版本
		if inheritVersion != mcVersion {
			continue
		}

		isBeta := strings.Contains(apiName, "beta")

		// 跳过已知不可用版本（参考 PCL：47.1.82）
		if apiName == "1.20.1-47.1.82" {
			continue
		}

		pkgName := "neoforge"
		if isLegacy {
			pkgName = "forge"
		}

		// BMCLAPI 镜像下载链接
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/neoforged/%s/%s/%s-%s-installer.jar",
			pkgName, apiName, pkgName, apiName,
		)

		// 提取显示版本号
		displayVersion := apiName
		if isLegacy {
			displayVersion = strings.TrimPrefix(apiName, "1.20.1-")
		}

		loaders = append(loaders, LoaderInfo{
			Name:         "neoforge",
			DisplayName:  "NeoForge",
			Version:      displayVersion,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       !isBeta,
			ForgeVersion: apiName,
		})
	}

	// 只保留最近 10 个版本
	if len(loaders) > 10 {
		loaders = loaders[len(loaders)-10:]
	}

	return loaders, nil
}

// fetchNeoForgeVersionList 从 API 获取版本列表（仅返回版本名数组）
func fetchNeoForgeVersionList(apiURL string) ([]string, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 尝试解析为 {"versions": [...]} 格式
	var data struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &data); err == nil && len(data.Versions) > 0 {
		return data.Versions, nil
	}

	// 尝试解析为 Maven 标准格式 {"version": [...]}
	var mavenData struct {
		Versions struct {
			Version []string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &mavenData); err == nil && len(mavenData.Versions.Version) > 0 {
		return mavenData.Versions.Version, nil
	}

	return nil, fmt.Errorf("无法解析版本列表")
}

// ===== OptiFine 版本获取 =====

// GetOptiFineVersions 获取 OptiFine 版本列表
func (a *App) GetOptiFineVersions(mcVersion string) ([]LoaderInfo, error) {
	apiURL := "https://bmclapi2.bangbang93.com/optifine/versionList"

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: HTTP %d", resp.StatusCode)
	}

	var allEntries []BMCLAPIOptiFineEntry
	if err := json.NewDecoder(resp.Body).Decode(&allEntries); err != nil {
		return nil, fmt.Errorf("解析 OptiFine 版本失败: %v", err)
	}

	loaders := []LoaderInfo{}
	for _, entry := range allEntries {
		if entry.MCVersion != mcVersion {
			continue
		}

		versionName := entry.Type + "_" + entry.Patch

		// BMCLAPI 镜像下载 URL
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
			entry.MCVersion, entry.Type, entry.Patch,
		)

		isPreview := strings.HasPrefix(entry.Filename, "preview_")

		loaders = append(loaders, LoaderInfo{
			Name:         "optifine",
			DisplayName:  "OptiFine",
			Version:      versionName,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       !isPreview,
			IsPreview:    isPreview,
			Patch:        entry.Patch,
			OptiFineType: entry.Type,
		})
	}

	return loaders, nil
}

// ===== 加载器安装（完全按照 PCL 的逻辑） =====

// extractForgeInstaller 提取 bangbang93 ForgeInstaller 到临时目录
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
func isOldForge(versionStr string) bool {
	// versionStr 类似 "1.16.5-34.1.0" 或 "34.1.0"
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1] // 取最后一段
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}

// InstallForge 安装 Forge（完全按照 PCL 逻辑）
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
func (a *App) installOldForge(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开 Forge 安装器失败: %v", err)
	}
	defer r.Close()

	// 读取 install_profile.json
	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("读取 install_profile.json 失败: %v", err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("读取 install_profile.json 失败: %v", err)
			}
			if err := json.Unmarshal(data, &installProfile); err != nil {
				return fmt.Errorf("解析 install_profile.json 失败: %v", err)
			}
			break
		}
	}

	if installProfile == nil {
		return fmt.Errorf("安装器中未找到 install_profile.json")
	}

	// 确定版本 ID（从 install_profile.json 中获取）
	targetVersion := ""
	if id, ok := installProfile["id"].(string); ok && id != "" {
		targetVersion = id
	}
	if targetVersion == "" {
		targetVersion = mcVersion + "-forge-unknown"
	}

	if err := validateVersionName(targetVersion); err != nil {
		return fmt.Errorf("安装器给出的版本名非法: %v", err)
	}
	versionFolder := filepath.Join(mcDir, "versions", targetVersion)

	// 创建版本文件夹
	if err := os.MkdirAll(versionFolder, 0755); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	if installProfile["install"] == nil {
		// 中版：Legacy 方式 1
		// 从安装器中提取版本 JSON
		jsonPath, _ := installProfile["json"].(string)
		if jsonPath == "" {
			return fmt.Errorf("install_profile.json 中缺少 json 字段")
		}
		jsonPath = strings.TrimPrefix(jsonPath, "/")

		var versionJSONData []byte
		for _, f := range r.File {
			if f.Name == jsonPath {
				rc, err := f.Open()
				if err != nil {
					return fmt.Errorf("读取版本 JSON 失败: %v", err)
				}
				versionJSONData, _ = io.ReadAll(rc)
				rc.Close()
				break
			}
		}

		if versionJSONData == nil {
			return fmt.Errorf("安装器中未找到 %s", jsonPath)
		}

		// 设置版本 ID 和 inheritsFrom
		var versionJSON map[string]interface{}
		if err := json.Unmarshal(versionJSONData, &versionJSON); err != nil {
			return fmt.Errorf("解析版本 JSON 失败: %v", err)
		}
		versionJSON["id"] = targetVersion
		if versionJSON["inheritsFrom"] == nil {
			versionJSON["inheritsFrom"] = mcVersion
		}

		// 保存版本 JSON
		outputData, _ := json.MarshalIndent(versionJSON, "", "  ")
		jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
		if err := os.WriteFile(jsonFilePath, outputData, 0644); err != nil {
			return fmt.Errorf("保存版本 JSON 失败: %v", err)
		}

		// 解压 maven 文件到 libraries 目录
		r.Close()
		if err := a.extractMavenFiles(installerPath, mcDir); err != nil {
			fmt.Printf("解压 maven 文件失败（可能不影响启动）: %v\n", err)
		}
	} else {
		// 旧版：Legacy 方式 2
		installInfo := installProfile["install"].(map[string]interface{})
		filePath, _ := installInfo["filePath"].(string)
		pathStr, _ := installInfo["path"].(string)

		// 提取 Jar 文件到 libraries
		if pathStr != "" && filePath != "" {
			libPath, safeErr := safeRelPath(filepath.Join(mcDir, "libraries"), pathStr)
			if safeErr != nil {
				fmt.Printf("拒绝越界的安装清单路径: %s\n", pathStr)
			} else {
				os.MkdirAll(filepath.Dir(libPath), 0755)

				for _, f := range r.File {
					if f.Name == filePath {
						rc, err := f.Open()
						if err != nil {
							break
						}
						data, _ := io.ReadAll(rc)
						rc.Close()
						os.WriteFile(libPath, data, 0644)
						break
					}
				}
			}
		}

		// 提取版本 JSON
		versionInfo := installProfile["versionInfo"]
		if versionInfo != nil {
			vi := versionInfo.(map[string]interface{})
			vi["id"] = targetVersion
			if vi["inheritsFrom"] == nil {
				vi["inheritsFrom"] = mcVersion
			}
			outputData, _ := json.MarshalIndent(vi, "", "  ")
			jsonFilePath := filepath.Join(versionFolder, targetVersion+".json")
			os.WriteFile(jsonFilePath, outputData, 0644)
		}
	}

	// 验证安装
	if !a.validateVersionInstallation(versionFolder) {
		os.RemoveAll(versionFolder)
		return fmt.Errorf("旧版 Forge 安装验证失败")
	}

	fmt.Printf("旧版 Forge 安装成功: %s\n", targetVersion)

	// 清理安装器
	os.Remove(installerPath)

	return nil
}

// extractMavenFiles 从安装器中解压 maven 文件到 libraries 目录
func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")

	for _, f := range r.File {
		// 只解压 maven/ 目录下的文件
		if strings.HasPrefix(f.Name, "maven/") && !f.FileInfo().IsDir() {
			relPath := strings.TrimPrefix(f.Name, "maven/")
			destPath, safeErr := safeRelPath(libsDir, relPath)
			if safeErr != nil {
				continue
			}

			os.MkdirAll(filepath.Dir(destPath), 0755)

			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			os.WriteFile(destPath, data, 0644)
		}
	}

	return nil
}

// downloadForgeLibraries 分析并下载 Forge 支持库文件
func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	// 读取 install_profile.json 和 version.json
	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &profileData)
		}
		if f.Name == "version.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &versionData)
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	// 合并两个 JSON 的 libraries
	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	// 下载每个支持库（先收集任务再带计数进度下载）
	libsDir := filepath.Join(mcDir, "libraries")
	type libDlTask struct {
		url  string
		path string
		name string
	}
	var libTasks []libDlTask
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
		if !ok {
			continue
		}

		// 获取下载信息
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

		// 替换为 BMCLAPI 镜像
		url = strings.Replace(url, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)

		destPath := filepath.Join(libsDir, path)
		if _, err := os.Stat(destPath); err == nil {
			continue // 已存在
		}

		libTasks = append(libTasks, libDlTask{url: url, path: destPath, name: filepath.Base(path)})
	}

	for i, task := range libTasks {
		a.emitProgress("downloading", fmt.Sprintf("支持库 %d/%d: %s", i+1, len(libTasks), task.name), int64(i+1), int64(len(libTasks)))
		if err := a.downloadFile(task.url, task.path, false); err != nil {
			fmt.Printf("下载支持库失败 %s: %v\n", task.name, err)
		}
	}

	// === 新版 Forge 需要 Mappings 文件（参考 PCL 的 DlClientFix） ===
	// install_profile.json 中的 data.MOJMAPS 字段引用了原版 MC 的 client_mappings
	dataSection, hasData := profileData["data"].(map[string]interface{})
	if !hasData {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
	} else if _, hasMojmaps := dataSection["MOJMAPS"]; hasMojmaps {
		fmt.Printf("检测到新版 Forge，需要下载 Mappings 文件\n")
		a.downloadForgeMappings(mcDir, mcVersion, installerPath)
	} else {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
	}

	return nil
}

// ensureForgeMappings 确保 Forge 新版需要的 Mappings 文件存在
// 使用 CMD 命令（Invoke-WebRequest）下载文件
func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	// 1. 从 install_profile.json 获取配置
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		a.writeLog("无法打开安装器（跳过 Mappings 检查）: %v", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	var mcVersion string
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()

			json.Unmarshal(data, &installProfile)

			// 获取 mcVersion - 新版 Forge 中 minecraft 是字符串格式 "1.19.2"
			if minecraftVal, ok := installProfile["minecraft"]; ok {
				if mv, ok := minecraftVal.(string); ok {
					mcVersion = mv
					a.writeLog("找到 mcVersion: %s", mcVersion)
				}
			}
			break
		}
	}

	if installProfile == nil || mcVersion == "" {
		a.writeLog("未找到 mcVersion（跳过 Mappings 检查）")
		return
	}

	// 2. 检查是否需要 MOJMAPS
	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 data 字段（跳过 Mappings 检查）")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 MOJMAPS 字段（跳过 Mappings 检查）")
		return
	}

	clientValue, ok := mojmapsData["client"].(string)
	if !ok || clientValue == "" {
		a.writeLog("未找到 MOJMAPS.client 字段（跳过 Mappings 检查）")
		return
	}

	// 解析 MOJMAPS.client: [net.minecraft:client:1.19.2-20220805.130853:mappings@txt]
	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	parts := strings.Split(originalName, ":")
	if len(parts) < 3 {
		a.writeLog("MOJMAPS.client Maven 格式错误（跳过 Mappings 检查）")
		return
	}

	groupPath := strings.Replace(parts[0], ".", "/", -1)
	artifact := parts[1]
	versionPart := parts[2]

	targetPath := filepath.Join(mcDir, "libraries", groupPath, artifact, versionPart,
		fmt.Sprintf("%s-%s-mappings.%s", artifact, versionPart, extension))

	a.writeLog("目标路径: %s", targetPath)

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		a.writeLog("Mappings 文件已存在: %s", targetPath)
		return
	}

	// 3. 从原版版本 JSON 获取 client_mappings URL
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		a.writeLog("无法读取原版版本 JSON: %v", err)
		return
	}

	var rawJSON map[string]interface{}
	json.Unmarshal(jsonData, &rawJSON)

	downloads, _ := rawJSON["downloads"].(map[string]interface{})
	if downloads == nil {
		a.writeLog("未找到 downloads 字段")
		return
	}

	clientMappings, _ := downloads["client_mappings"].(map[string]interface{})
	if clientMappings == nil {
		a.writeLog("未找到 client_mappings 字段")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		a.writeLog("未找到 client_mappings URL")
		return
	}

	// 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	a.writeLog("使用 CMD 命令下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 4. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 5. 使用 PowerShell Invoke-WebRequest 下载文件（带 User-Agent 避免被拦截）
	a.writeLog("执行下载命令...")
	downloadCmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $headers = @{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1'}; Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing -Headers $headers",
			mappingsURL, targetPath))
	downloadCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := downloadCmd.CombinedOutput()

	if err != nil {
		a.writeLog("CMD 下载失败: %v, 输出: %s", err, string(output))
		return
	}

	// 6. 验证文件是否存在且不为空
	fileInfo, statErr := os.Stat(targetPath)
	if statErr != nil {
		a.writeLog("下载后验证文件失败: %v", statErr)
		return
	}

	if fileInfo.Size() == 0 {
		a.writeLog("下载的文件为空！删除空文件")
		os.Remove(targetPath)
		return
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}

// downloadForgeMappings 下载 Forge 新版所需的 client_mappings 文件（保留旧函数以保持兼容性）
// Forge 安装器期望的路径格式: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	// 1. 从 install_profile.json 获取 MOJMAPS 配置
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	// 2. 获取 MOJMAPS 数据（包含 mcpVersion）
	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
		return
	}

	mcpVersion, ok := mojmapsData["version"].(string)
	if !ok || mcpVersion == "" {
		fmt.Printf("未找到 MOJMAPS.version 字段（跳过 Mappings 下载）\n")
		return
	}

	fmt.Printf("检测到 Forge MOJMAPS: %s\n", mcpVersion)

	// 3. 构建目标路径
	// Forge 安装器期望的路径: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
	targetPath := filepath.Join(mcDir, "libraries", "net", "minecraft", "client", mcpVersion, fmt.Sprintf("client-%s-mappings.txt", mcpVersion))

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	// 4. 尝试从原版版本 JSON 获取 client_mappings 下载信息
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("无法读取原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	var rawJSON map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawJSON); err != nil {
		fmt.Printf("解析原版版本 JSON 失败（跳过 Mappings 下载）: %v\n", err)
		return
	}

	downloads, ok := rawJSON["downloads"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 downloads 字段（跳过 Mappings 下载）\n")
		return
	}

	clientMappings, ok := downloads["client_mappings"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 client_mappings 字段（跳过 Mappings 下载）\n")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		fmt.Printf("未找到 client_mappings URL（跳过 Mappings 下载）\n")
		return
	}

	// 5. 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	// 6. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 7. 下载文件（先下载为临时文件，然后重命名）
	tempPath := targetPath + ".tmp"
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFile(mappingsURL, tempPath, false); err != nil {
		// 如果临时文件已存在，删除它
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	// 8. 重命名为 Forge 安装器期望的名称
	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

// ensureLauncherProfiles 确保 launcher_profiles.json 存在（Forge 安装器需要）
func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		data, _ := json.MarshalIndent(profiles, "", "  ")
		os.WriteFile(profilesPath, data, 0644)
	}
}

// getVersionFolderList 获取当前版本文件夹列表
func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

// runForgeInstaller 运行 bangbang93 ForgeInstaller（完全按照 PCL 的命令行）
func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	// 0. 确保新版 Forge 需要的 Mappings 文件存在（参考 PCL 的 DlClientFix）
	a.ensureForgeMappings(installerPath, mcDir)

	// 1. 提取 bangbang93 ForgeInstaller
	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	// 2. 选择 Java
	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	// 3. 构造命令行参数（完全按照 PCL 的方式）
	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 4. 启动进程
	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// 5. 使用 CombinedOutput 捕获完整输出
	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	// 写入完整输出到日志
	a.writeLog("----- ForgeInstaller 输出开始 -----")
	if outputStr != "" {
		for _, line := range strings.Split(outputStr, "\n") {
			a.writeLog("  %s", line)
		}
	} else {
		a.writeLog("  (无输出)")
	}
	a.writeLog("----- ForgeInstaller 输出结束 -----")
	if runErr != nil {
		a.writeLog("进程退出错误: %v", runErr)
	}

	// 6. 检查输出中是否有 "true"（bangbang93 安装器成功标志，只看最后4行）
	lines := strings.Split(outputStr, "\n")
	var lastLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			lastLines = append(lastLines, line)
		}
	}

	foundTrue := false
	checkCount := 4
	if len(lastLines) < checkCount {
		checkCount = len(lastLines)
	}
	for _, line := range lastLines[len(lastLines)-checkCount:] {
		if line == "true" {
			foundTrue = true
			break
		}
	}

	if foundTrue {
		a.writeLog("检测到安装器成功标志 'true'，安装成功")
		return nil
	}

	// 严格按照用户要求：未检测到 "true" 标志即为安装失败，即使版本文件夹存在也不例外
	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	// 8. 返回详细错误信息
	if runErr != nil {
		errMsg := fmt.Errorf("Forge 安装器运行失败\nJava: %s (v%d)\n错误: %v\n\n完整输出:\n%s",
			javaEntry.Path, javaEntry.MajorVer, runErr, outputStr)
		a.writeLog("Forge 安装最终失败: %v", errMsg)
		return errMsg
	}

	errMsg := fmt.Errorf("Forge 安装器未返回成功标志\nJava: %s (v%d)\n\n完整输出:\n%s",
		javaEntry.Path, javaEntry.MajorVer, outputStr)
	a.writeLog("Forge 安装最终失败: %v", errMsg)
	return errMsg
}

// findNewVersionFolder 查找安装器新创建的版本文件夹
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

	destPath, safeErr := safeRelPath(tempDir, fileName)
	if safeErr != nil {
		return fmt.Errorf("非法目标文件名: %s", fileName)
	}

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
