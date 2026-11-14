package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

)

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
