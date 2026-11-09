package main

import (
	"fmt"
	"net/http"
)

// ===== Forge 版本获取 =====

func (a *App) GetForgeVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	apiURL := fmt.Sprintf("https://bmclapi2.bangbang93.com/forge/minecraft/%s", mcVersion)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Forge 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Forge 版本失败: HTTP %d", resp.StatusCode)
	}

	var entries []BMCLAPIForgeEntry
	if err := readAPIJSON(resp, &entries); err != nil {
		return nil, fmt.Errorf("解析 Forge 版本失败: %v", err)
	}

	recommendedVersion := ""
	if promosResp, promosErr := safeHTTPClient().Get("https://bmclapi2.bangbang93.com/forge/promos"); promosErr == nil && promosResp.StatusCode == http.StatusOK {
		var promos map[string]string
		if promosErr2 := readAPIJSON(promosResp, &promos); promosErr2 == nil {
			recommendedVersion = promos[mcVersion+"-recommended"]
		}
		promosResp.Body.Close()
	}

	loaders := []LoaderInfo{}
	for _, entry := range entries {
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

// isValidMCVersion 验证 Minecraft 版本号格式
// 防止版本号注入攻击，只允许数字、点、下划线和字母
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
