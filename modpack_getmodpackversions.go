package main

import (
	"context"
	"encoding/json"
	"fmt"

)

func (a *App) GetModpackVersions(projectID string) ([]ModVersion, error) {
	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)

	body, err := fetchBounded(context.Background(), apiURL, defaultSafeHTTPOptions())
	if err != nil {
		return nil, fmt.Errorf("获取整合包版本失败: %v", err)
	}

	var versions []ModVersion
	if err := json.Unmarshal(body, &versions); err != nil {
		return nil, fmt.Errorf("解析版本列表失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}

	return versions, nil
}

// AddModpackToDownloadList 添加整合包到下载列表
