package main

import (
	"encoding/json"
	"fmt"
	"net/http"

)

func (a *App) GetModDependencies(versionID string) ([]ModDependencyInfo, error) {
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return nil, fmt.Errorf("解析版本详情失败: %v", err)
	}

	var deps []ModDependencyInfo
	if version.Dependencies == nil {
		return deps, nil
	}
	for _, dep := range version.Dependencies {
		if dep.ProjectID == "" {
			continue
		}

		depInfo := ModDependencyInfo{
			ProjectID:      dep.ProjectID,
			DependencyType: dep.DependencyType,
		}

		detail, err := a.GetModDetail(dep.ProjectID)
		if err == nil && detail != nil {
			depInfo.ProjectName = detail.Title
			depInfo.IconURL = detail.IconURL
		} else {
			depInfo.ProjectName = dep.ProjectID
		}

		deps = append(deps, depInfo)
	}

	return deps, nil
}

// AddModToDownloadList 添加 Mod 到下载列表
