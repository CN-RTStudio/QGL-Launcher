package main

import (
	"fmt"
	"net/http"
)

func (a *App) GetModDetail(projectID string) (*ModDetail, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的 Mod ID 格式")
	}

	apiURL := fmt.Sprintf("%s/project/%s", modrinthBaseURL, projectID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 Mod 详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 Mod 详情失败: HTTP %d", resp.StatusCode)
	}

	var detail ModDetail
	if err := readAPIJSON(resp, &detail); err != nil {
		return nil, fmt.Errorf("解析 Mod 详情失败: %v", err)
	}

	return &detail, nil
}
