package main

import (
	"fmt"
	"net/http"
)

// GetModrinthCategories 获取 Modrinth 分类标签
func (a *App) GetModrinthCategories() ([]ModCategory, error) {
	apiURL := fmt.Sprintf("%s/tag/category", modrinthBaseURL)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取分类失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取分类失败: HTTP %d", resp.StatusCode)
	}

	var categories []ModCategory
	if err := readAPIJSON(resp, &categories); err != nil {
		return nil, fmt.Errorf("解析分类失败: %v", err)
	}

	modCategories := []ModCategory{}
	for _, cat := range categories {
		if cat.ProjectType == "mod" {
			modCategories = append(modCategories, cat)
		}
	}

	return modCategories, nil
}
