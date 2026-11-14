package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

)

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
