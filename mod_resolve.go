package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) ResolveModDependencies(versionIDs []string, gameVersion string, loader string) ([]ModDependencyResult, error) {
	var results []ModDependencyResult
	visited := make(map[string]bool)

	for _, vid := range versionIDs {
		if !isValidModID(vid) {
			continue
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			continue
		}
		var version ModVersion
		if err := readAPIJSON(resp, &version); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if version.ProjectID != "" {
			visited[version.ProjectID] = true
		}
	}

	var resolveDeps func(vid string, depth int) error
	resolveDeps = func(vid string, depth int) error {
		if depth > 5 {
			return nil
		}

		if !isValidModID(vid) {
			return nil
		}

		apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, vid)
		resp, err := safeHTTPClient().Get(apiURL)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		var version ModVersion
		if err := readAPIJSON(resp, &version); err != nil {
			return nil
		}

		for _, dep := range version.Dependencies {
			if dep.DependencyType == "optional" || dep.DependencyType == "embedded" {
				continue
			}
			if dep.DependencyType != "required" {
				continue
			}
			if dep.ProjectID == "" {
				continue
			}
			if visited[dep.ProjectID] {
				continue
			}
			visited[dep.ProjectID] = true

			detail, err := a.GetModDetail(dep.ProjectID)
			if err != nil {
				continue
			}

			depVersionID := dep.VersionID
			if depVersionID == "" {
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

			_ = resolveDeps(depVersionID, depth+1)
		}
		return nil
	}

	for _, vid := range versionIDs {
		_ = resolveDeps(vid, 0)
	}

	return results, nil
}

type ModDependencyResult struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	VersionID      string `json:"versionId"`
	DependencyType string `json:"dependencyType"`
}

func (a *App) SelectModSaveDir() (string, error) {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Mod 保存位置",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}
