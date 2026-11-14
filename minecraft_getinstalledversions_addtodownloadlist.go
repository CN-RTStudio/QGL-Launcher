package main

import (
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        versionURL,
		CustomName: customName,
		Type:       versionType,
		ItemType:   "game",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddToDownloadListWithLoader 添加带加载器的游戏到下载列表
