package main

import (
	"encoding/json"
	"fmt"
	"net/http"

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
