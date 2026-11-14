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
func (a *App) AddJavaToDownloadList(majorVer int) error {
	javaList := a.GetJavaDownloadList()
	var target *JavaDownloadInfo
	for i := range javaList {
		if javaList[i].MajorVer == majorVer {
			target = &javaList[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到 Java %d 的下载信息", majorVer)
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	customName := "Java " + fmt.Sprintf("%d", majorVer)
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         fmt.Sprintf("java-%d", majorVer),
		URL:        target.URL,
		CustomName: customName,
		Type:       "java",
		ItemType:   "java",
		JavaMajor:  majorVer,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// RemoveFromDownloadList 从下载列表移除
