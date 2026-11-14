package main

import (
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) emitProgress(status string, currentFile string, downloaded, total int64) {
	// 节流：非终态且距上次发送不足 100ms 时跳过
	if status != "completed" && status != "failed" {
		if time.Since(lastProgressEmit) < 100*time.Millisecond {
			// 仍然更新内存中的进度，但不发事件
			var pct float64
			if total > 0 {
				pct = float64(downloaded) / float64(total) * 100
			}
			a.downloadMutex.Lock()
			for i := range a.downloadList {
				if a.downloadList[i].Status == "downloading" {
					a.downloadList[i].Progress = a.mapProgressToScale(pct)
					a.downloadList[i].CurrentStep = currentFile
					break
				}
			}
			a.downloadMutex.Unlock()
			return
		}
	}
	lastProgressEmit = time.Now()

	var pct float64
	if total > 0 {
		pct = float64(downloaded) / float64(total) * 100
	}
	a.downloadProgress = DownloadProgress{
		TotalBytes:      total,
		DownloadedBytes: downloaded,
		Percentage:      pct,
		CurrentFile:     currentFile,
		Status:          status,
	}

	// 更新下载列表中正在下载项的进度（映射到阶段区间）
	a.downloadMutex.Lock()
	for i := range a.downloadList {
		if a.downloadList[i].Status == "downloading" {
			a.downloadList[i].Progress = a.mapProgressToScale(pct)
			a.downloadList[i].CurrentStep = currentFile
			break
		}
	}
	a.downloadMutex.Unlock()

	runtime.EventsEmit(a.ctx, "downloadProgress", a.downloadProgress)
	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
}

// emitFixProgress 启动补全阶段的进度上报：
// 除常规 downloadProgress（下载列表）外，同时发 launchFixProgress（启动界面遮罩显示步骤文本），
// 否则启动界面只会显示静态的"补全文件中..."，用户会以为卡死
