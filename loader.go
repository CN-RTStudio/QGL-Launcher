package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
