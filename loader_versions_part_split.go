package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func fetchNeoForgeVersionList(apiURL string) ([]string, error) {
	if !isHTTPSURL(apiURL) {
		return nil, fmt.Errorf("不安全的 URL 协议")
	}

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return nil, err
	}

	var data struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &data); err == nil && len(data.Versions) > 0 {
		return data.Versions, nil
	}

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

func (a *App) GetOptiFineVersions(mcVersion string) ([]LoaderInfo, error) {
	if !isValidMCVersion(mcVersion) {
		return nil, fmt.Errorf("无效的 Minecraft 版本格式")
	}

	client := safeHTTPClient()
	apiURL := "https://bmclapi2.bangbang93.com/optifine/versionList"

	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: HTTP %d", resp.StatusCode)
	}

	var allEntries []BMCLAPIOptiFineEntry
	if err := readAPIJSON(resp, &allEntries); err != nil {
		return nil, fmt.Errorf("解析 OptiFine 版本失败: %v", err)
	}

	loaders := []LoaderInfo{}
	for _, entry := range allEntries {
		if entry.MCVersion != mcVersion {
			continue
		}

		versionName := entry.Type + "_" + entry.Patch

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
