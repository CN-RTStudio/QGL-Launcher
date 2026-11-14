package main

import (
	"context"
	"encoding/json"
	"fmt"

)

func (a *App) ResolveModDependencies(versionIDs []string, gameVersion string, loader string) ([]ModDependencyResult, error) {
	var results []ModDependencyResult
	visited := make(map[string]bool) // 已处理的 projectID

	// 先把用户已选择的 mod 标记为已处理
	for _, vid := range versionIDs {
		// 获取版本信息以获取 projectID
		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		body, err := fetchBounded(context.Background(), apiURL, defaultSafeHTTPOptions())
		if err != nil {
			continue
		}
		var version ModVersion
		if err := json.Unmarshal(body, &version); err != nil {
			continue
		}
		if version.ProjectID != "" {
			visited[version.ProjectID] = true
		}
	}

	// 递归解析依赖
	var resolveDeps func(vid string, depth int) error
	resolveDeps = func(vid string, depth int) error {
		if depth > 5 {
			return nil // 防止无限递归
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		body, err := fetchBounded(context.Background(), apiURL, defaultSafeHTTPOptions())
		if err != nil {
			return nil
		}

		var version ModVersion
		if err := json.Unmarshal(body, &version); err != nil {
			return nil
		}

		for _, dep := range version.Dependencies {
			// 跳过可选依赖和嵌入式依赖
			if dep.DependencyType == "optional" || dep.DependencyType == "embedded" {
				continue
			}
			// 只处理必需依赖
			if dep.DependencyType != "required" {
				continue
			}
			if dep.ProjectID == "" {
				continue
			}
			// 跳过已处理的
			if visited[dep.ProjectID] {
				continue
			}
			visited[dep.ProjectID] = true

			// 获取依赖 mod 的详情
			detail, err := a.GetModDetail(dep.ProjectID)
			if err != nil {
				continue
			}

			// 如果有 version_id，直接使用；否则查找兼容版本
			depVersionID := dep.VersionID
			if depVersionID == "" {
				// 查找兼容的版本
				versions, err := a.GetModVersions(dep.ProjectID, gameVersion, loader)
				if err != nil || len(versions) == 0 {
					continue
				}
				depVersionID = versions[0].ID
			}

			results = append(results, ModDependencyResult{
				ProjectID:      dep.ProjectID,
				ProjectName:    detail.Title,
				IconURL:        detail.IconURL,
				VersionID:      depVersionID,
				DependencyType: dep.DependencyType,
			})

			// 递归解析此依赖的依赖
			_ = resolveDeps(depVersionID, depth+1)
		}
		return nil
	}

	// 解析所有用户选择的 mod 的依赖
	for _, vid := range versionIDs {
		_ = resolveDeps(vid, 0)
	}

	return results, nil
}

// ModDependencyResult 依赖解析结果
type ModDependencyResult struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	VersionID      string `json:"versionId"`
	DependencyType string `json:"dependencyType"`
}

// SelectModSaveDir 弹出选择 Mod 保存目录对话框
