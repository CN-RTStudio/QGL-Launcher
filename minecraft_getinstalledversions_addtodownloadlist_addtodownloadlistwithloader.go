package main

import (
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:             versionID,
		URL:            versionURL,
		CustomName:     displayName,
		Type:           versionType,
		ItemType:       "game+loader",
		LoaderName:     loaderName,
		LoaderVersion:  loaderVersion,
		OptiFineType:   optifineType,
		OptiFinePatch:  optifinePatch,
		Status:         "pending",
		Progress:       0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddJavaToDownloadList 添加 Java 到下载列表
