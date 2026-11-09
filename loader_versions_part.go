package main

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *App) GetFabricVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	client := safeHTTPClient()
	fabricMetaURL := "https://bmclapi2.bangbang93.com/fabric-meta/v2/versions"

	resp, err := client.Get(fabricMetaURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = safeHTTPClient().Get("https://meta.fabricmc.net/v2/versions")
		if err != nil {
			return nil, fmt.Errorf("获取 Fabric 版本失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Fabric 版本失败: HTTP %d", resp.StatusCode)
	}

	var fabricMeta struct {
		Game []struct {
			Version string `json:"version"`
			Stable  bool   `json:"stable"`
		} `json:"game"`
		Loader []FabricLoaderVersion `json:"loader"`
	}
	if err := readAPIJSON(resp, &fabricMeta); err != nil {
		return nil, fmt.Errorf("解析 Fabric 版本失败: %v", err)
	}

	mcVersionNormalized := mcVersion
	supported := false
	for _, g := range fabricMeta.Game {
		if g.Version == mcVersionNormalized {
			supported = true
			break
		}
	}
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

func (a *App) GetNeoForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	major, minor, patch := parseMCVersion(mcVersion)
	mcNum := major*1000 + minor*100 + patch
	if mcNum < 1201 {
		return []LoaderInfo{}, nil
	}

	var allVersions []string

	legacyURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/forge"
	if entries, err := fetchNeoForgeVersionList(legacyURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

	latestURL := "https://bmclapi2.bangbang93.com/neoforge/meta/api/maven/details/releases/net/neoforged/neoforge"
	if entries, err := fetchNeoForgeVersionList(latestURL); err == nil {
		allVersions = append(allVersions, entries...)
	}

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
		isLegacy := strings.Contains(apiName, "1.20.1")
		inheritVersion := ""

		if isLegacy {
			inheritVersion = "1.20.1"
		} else {
			versionPart := apiName
			if idx := strings.Index(apiName, "-"); idx > 0 {
				versionPart = apiName[:idx]
			}
			parts := strings.Split(versionPart, ".")
			if len(parts) >= 2 {
				nfMajor := parts[0]
				nfMinor := parts[1]
				if nfMinor == "0" {
					inheritVersion = "1." + nfMajor
				} else {
					inheritVersion = "1." + nfMajor + "." + nfMinor
				}
			}
		}

		if inheritVersion != mcVersion {
			continue
		}

		isBeta := strings.Contains(apiName, "beta")

		if apiName == "1.20.1-47.1.82" {
			continue
		}

		pkgName := "neoforge"
		if isLegacy {
			pkgName = "forge"
		}

		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/maven/net/neoforged/%s/%s/%s-%s-installer.jar",
			pkgName, apiName, pkgName, apiName,
		)

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

	if len(loaders) > 10 {
		loaders = loaders[len(loaders)-10:]
	}

	return loaders, nil
}
