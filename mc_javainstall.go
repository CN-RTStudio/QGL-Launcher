package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

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
	if majorVer < 0 || majorVer > 99 {
		return fmt.Errorf("Java 主版本号超出合理范围: %d", majorVer)
	}
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	customName := "Java " + fmt.Sprintf("%d", majorVer)
	pending := DownloadItem{
		ID: fmt.Sprintf("java-%d", majorVer), URL: target.URL, CustomName: customName,
		Type: "java", ItemType: "java", JavaMajor: majorVer, Status: "pending", Progress: 0,
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
