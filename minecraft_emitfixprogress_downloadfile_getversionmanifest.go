package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

)

func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}

	var body []byte
	var lastErr error

	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", lastErr)
	}

	var manifest VersionManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("解析版本清单失败: %v", err)
	}

	var result []MCVersion
	for _, v := range manifest.Versions {
		if v.Type == "release" || v.Type == "snapshot" {
			result = append(result, MCVersion{
				ID:          v.ID,
				Type:        v.Type,
				URL:         v.URL,
				ReleaseTime: v.ReleaseTime,
			})
		}
	}

	return result, nil
}

// GetInstalledVersions 获取已安装的版本列表（仅读取，不扫描创建 config.json）
