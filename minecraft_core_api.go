package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) getMinecraftDir() string { return a.GetMinecraftDir() }
func (a *App) emitProgress(status string, currentFile string, downloaded, total int64) {
	var pct float64
	if total > 0 {
		pct = float64(downloaded) / float64(total) * 100
	}
	a.downloadProgress = DownloadProgress{
		TotalBytes: total, DownloadedBytes: downloaded, Percentage: pct,
		CurrentFile: currentFile, Status: status,
	}
	a.downloadMutex.Lock()
	for i := range a.downloadList {
		if a.downloadList[i].Status == "downloading" {
			a.downloadList[i].Progress = pct
			break
		}
	}
	a.downloadMutex.Unlock()
	runtime.EventsEmit(a.ctx, "downloadProgress", a.downloadProgress)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
}

func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	// 版本名会直接成为 versions/<name>/<name>.json 的目录段，走严格名单段内核：
	// 控制字符、路径分隔符、Windows 保留设备名、尾点空格、超长一律拒绝（而不是像旧
	// sanitizeVersionName 那样静默删字符，导致用户以为写入的目录与实际不一致）。
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本下载名: "+describeNameReject(why))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(why))
	}
	customName = safeName
	pending := DownloadItem{
		ID: versionID, URL: versionURL, CustomName: customName,
		Type: versionType, ItemType: "game", Status: "pending", Progress: 0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}
	a.downloadList = append(a.downloadList, pending)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

func (a *App) RemoveFromDownloadList(customName string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	for i, item := range a.downloadList {
		if item.CustomName == customName {
			a.downloadList = append(a.downloadList[:i], a.downloadList[i+1:]...)
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			return nil
		}
	}
	return fmt.Errorf("未找到: %s", customName)
}
