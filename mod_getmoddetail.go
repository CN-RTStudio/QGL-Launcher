package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

)

func (a *App) GetModDetail(projectID string) (*ModDetail, error) {
	apiURL := fmt.Sprintf("%s/project/%s", modrinthBaseURL, projectID)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 详情失败: HTTP %d", resp.StatusCode)
	}

	var detail ModDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("解析 Mod 详情失败: %v", err)
	}

	return &detail, nil
}

// GetModVersions 获取 Mod 版本列表
func (a *App) GetModVersions(projectID string, gameVersion string, loader string) ([]ModVersion, error) {
	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)

	params := url.Values{}
	if gameVersion != "" {
		gvJSON, _ := json.Marshal([]string{gameVersion})
		params.Set("game_versions", string(gvJSON))
	}
	if loader != "" {
		loaderJSON, _ := json.Marshal([]string{loader})
		params.Set("loaders", string(loaderJSON))
	}

	if len(params) > 0 {
		apiURL += "?" + params.Encode()
	}

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 版本失败: HTTP %d", resp.StatusCode)
	}

	var versions []ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, fmt.Errorf("解析 Mod 版本失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}
	for i := range versions {
		if versions[i].GameVersions == nil {
			versions[i].GameVersions = []string{}
		}
		if versions[i].Loaders == nil {
			versions[i].Loaders = []string{}
		}
		if versions[i].Files == nil {
			versions[i].Files = []ModFile{}
		}
		if versions[i].Dependencies == nil {
			versions[i].Dependencies = []ModDependency{}
		}
	}

	return versions, nil
}

// GetModDependencies 获取 Mod 依赖信息
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
