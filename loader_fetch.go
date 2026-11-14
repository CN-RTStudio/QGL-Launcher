package main

import (
	"fmt"
	"net/http"
)

func isValidMCVersion(version string) bool {
	if len(version) > 20 {
		return false
	}
	for _, r := range version {
		if !((r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ===== Fabric 版本获取 =====

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
