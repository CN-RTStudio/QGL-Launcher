package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

)

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
