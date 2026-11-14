package main

import (
	"context"
	"encoding/json"
	"fmt"

)

func (a *App) GetModDetail(projectID string) (*ModDetail, error) {
	apiURL := fmt.Sprintf("%s/project/%s", modrinthBaseURL, projectID)

	body, err := fetchBounded(context.Background(), apiURL, defaultSafeHTTPOptions())
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 详情失败: %v", err)
	}

	var detail ModDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return nil, fmt.Errorf("解析 Mod 详情失败: %v", err)
	}

	return &detail, nil
}

// GetModVersions 获取 Mod 版本列表
