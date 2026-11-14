package main

import (
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) StartDownloadList() error {
	a.downloadMutex.Lock()
	if a.isDownloading {
		a.downloadMutex.Unlock()
		return nil // 已在下载中，循环会自动处理剩余 pending 项
	}
	if len(a.downloadList) == 0 {
		a.downloadMutex.Unlock()
		return fmt.Errorf("下载列表为空")
	}
	hasPending := false
	for i := range a.downloadList {
		if a.downloadList[i].Status == "pending" {
			hasPending = true
			break
		}
	}
	if !hasPending {
		a.downloadMutex.Unlock()
		return fmt.Errorf("没有待下载的项目")
	}
	a.isDownloading = true
	a.downloadCancel = make(chan struct{})
	a.downloadMutex.Unlock()

	go func() {
		defer func() {
			// 捕获任何 panic，保证 isDownloading 一定复位、完成事件一定发出，
			// 否则前端下载按钮会永久卡在"下载中"
			if r := recover(); r != nil {
				a.writeLog("下载列表处理发生崩溃: %v", r)
				a.downloadMutex.Lock()
				for i := range a.downloadList {
					if a.downloadList[i].Status == "downloading" {
						a.downloadList[i].Status = "failed"
						a.downloadList[i].ErrorMsg = fmt.Sprintf("内部错误: %v", r)
					}
					if a.downloadList[i].Status == "pending" {
						a.downloadList[i].Status = "cancelled"
					}
				}
				a.downloadMutex.Unlock()
			}
			a.downloadMutex.Lock()
			a.isDownloading = false
			a.downloadCancel = nil
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
			runtime.EventsEmit(a.ctx, "downloadListCompleted")
		}()

		for {
			// 检查是否取消
			select {
			case <-a.downloadCancel:
				// 将所有 pending 状态重置（downloading 的保持不变）
				a.downloadMutex.Lock()
				for i := range a.downloadList {
					if a.downloadList[i].Status == "pending" {
						a.downloadList[i].Status = "cancelled"
					}
				}
				a.downloadMutex.Unlock()
				runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
				return
			default:
			}

			a.downloadMutex.Lock()
			var item *DownloadItem
			idx := -1
			for i := range a.downloadList {
				if a.downloadList[i].Status == "pending" {
					item = &a.downloadList[i]
					idx = i
					break
				}
			}
			if item == nil {
				a.downloadMutex.Unlock()
				break
			}
			a.downloadList[idx].Status = "downloading"
			a.downloadMutex.Unlock()

			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())

			var err error
			// 每个项目重置进度映射为全区间（各函数内部会按阶段重新划分）
			a.setProgressScale(0, 100)
			if item.ItemType == "java" {
				err = a.downloadJavaItem(item.JavaMajor, item.URL)
			} else if item.ItemType == "mod" {
				err = a.downloadModItem(item)
			} else if item.ItemType == "loader" {
				err = a.downloadLoaderItem(item)
			} else if item.ItemType == "modpack" {
				err = a.installModpack(item)
			} else if item.ItemType == "game+loader" {
				// 原版下载占 0-65%，加载器安装占 65-95%，验证占 95-100%
				a.emitProgress("downloading", "下载原版游戏 "+item.ID, 0, 0)
				a.setProgressScale(0, 65)
				if err = a.DownloadVersion(item.ID, item.URL, item.ID); err != nil {
					err = fmt.Errorf("下载原版游戏失败: %v", err)
				} else {
					a.setProgressScale(65, 95)
					a.emitProgress("downloading", "安装 "+item.LoaderName+" "+item.LoaderVersion, 0, 0)
					switch item.LoaderName {
					case "forge":
						err = a.InstallForge(item.ID, item.LoaderVersion)
					case "fabric":
						err = a.InstallFabric(item.ID, item.LoaderVersion)
					case "neoforge":
						err = a.InstallNeoForge(item.ID, item.LoaderVersion)
					case "optifine":
						err = a.InstallOptiFine(item.ID, item.OptiFineType, item.OptiFinePatch)
					}
					if err != nil {
						err = fmt.Errorf("安装加载器失败: %v", err)
					}
				}
			} else {
				err = a.DownloadVersion(item.ID, item.URL, item.CustomName)
			}

			a.downloadMutex.Lock()
			if err != nil {
				a.downloadList[idx].Status = "failed"
				a.downloadList[idx].Progress = 0
				a.downloadList[idx].CurrentStep = ""
				a.downloadList[idx].ErrorMsg = err.Error()
			} else {
				a.downloadList[idx].Status = "completed"
				a.downloadList[idx].Progress = 100
				a.downloadList[idx].CurrentStep = ""
			}
			a.downloadMutex.Unlock()

			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
		}
	}()

	return nil
}

// CancelDownloadList 取消下载列表中的剩余任务
