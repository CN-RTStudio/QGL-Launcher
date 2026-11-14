package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) AddModpackToDownloadList(versionID string, customName string) error {
	// 获取版本详情以拿到下载链接
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取整合包版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取整合包版本详情失败: HTTP %d", resp.StatusCode)
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
		return fmt.Errorf("未找到整合包文件")
	}

	displayName := customName
	if displayName == "" {
		displayName = primaryFile.Filename
		if displayName == "" {
			displayName = version.Name
		}
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == displayName {
			return fmt.Errorf("下载列表中已存在: %s", displayName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: displayName,
		Type:       "modpack",
		ItemType:   "modpack",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// installModpack 安装整合包（参考 PCL ModModpack 逻辑）
// 流程：下载 .mrpack → 解析 manifest → 下载游戏 → 安装 loader → 下载所有 mod → 解压 overrides
