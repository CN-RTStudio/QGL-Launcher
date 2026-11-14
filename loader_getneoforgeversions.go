package main

import (
	_ "embed"
	"fmt"
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
