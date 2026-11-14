package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) AddModToDownloadList(versionID string, savePath string) error {
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return fmt.Errorf("解析版本详情失败: %v", err)
	}

	var primaryFile *ModFile
	for i := range version.Files {
		if version.Files[i].Primary {
			primaryFile = &version.Files[i]
			break
		}
	}
	if primaryFile == nil && len(version.Files) > 0 {
		primaryFile = &version.Files[0]
	}
	if primaryFile == nil {
		return fmt.Errorf("未找到 Mod 文件")
	}

	if savePath == "" {
		mcDir := a.GetMinecraftDir()
		savePath = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(savePath, 0755); err != nil {
		return fmt.Errorf("创建保存目录失败: %v", err)
	}

	customName := primaryFile.Filename
	if customName == "" {
		customName = version.Name
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: customName,
		Type:       "mod",
		ItemType:   "mod",
		SavePath:   savePath,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// ResolveModDependencies 解析 mod 的前置依赖，返回需要安装的依赖 mod 列表
// 递归解析依赖，跳过已选择的 mod 和可选依赖
// gameVersion 和 loader 用于筛选兼容的依赖版本
func (a *App) ResolveModDependencies(versionIDs []string, gameVersion string, loader string) ([]ModDependencyResult, error) {
	var results []ModDependencyResult
	visited := make(map[string]bool) // 已处理的 projectID

	// 先把用户已选择的 mod 标记为已处理
	for _, vid := range versionIDs {
		// 获取版本信息以获取 projectID
		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := http.Get(apiURL)
		if err != nil {
			continue
		}
		var version ModVersion
		if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
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
		resp, err := http.Get(apiURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		var version ModVersion
		if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
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
