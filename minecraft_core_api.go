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

func (a *App) GetDownloadList() []DownloadItem {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	result := make([]DownloadItem, len(a.downloadList))
	copy(result, a.downloadList)
	return result
}

func (a *App) GetDownloadListCount() int {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	return len(a.downloadList)
}

func (a *App) StartDownloadList() error {
	a.downloadMutex.Lock()
	if a.isDownloading {
		a.downloadMutex.Unlock()
		return fmt.Errorf("正在下载中，请等待当前下载完成")
	}
	if len(a.downloadList) == 0 {
		a.downloadMutex.Unlock()
		return fmt.Errorf("下载列表为空")
	}
	// r35：开始下载前做“分目录磁盘余量预检”。按各 pending 条目的 SavePath 聚合已知
	// 声明大小，逐卷探测剩余空间，任何目录写入会击穿 1GiB 安全水位就整体拒绝开始，
	// 避免把盘写到耗尽。未知大小 / 探测失败一律不拦（没有证据不能误杀）。
	demands := groupDownloadDiskDemand(a.downloadList)
	plans := planDownloadDiskFit(demands, probeDownloadDiskFit)
	if blocked := blockingDiskPlans(plans); len(blocked) > 0 {
		for _, bp := range blocked {
			recordSecurityEvent("download", auditSeverityCritical, auditActionBlocked,
				"disk-space", describeDiskPlanBlock(bp))
		}
		a.downloadMutex.Unlock()
		return fmt.Errorf("%s", describeDiskPlanBlock(blocked[0]))
	}
	a.isDownloading = true
	a.downloadCancel = make(chan struct{})
	a.downloadMutex.Unlock()
	go func() {
		defer func() {
			a.downloadMutex.Lock()
			a.isDownloading = false
			a.downloadCancel = nil
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListCompleted")
		}()
		for {
			select {
			case <-a.downloadCancel:
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
			if item.ItemType == "java" {
				err = a.downloadJavaItem(item.JavaMajor, item.URL)
			} else if item.ItemType == "mod" {
				err = a.downloadModItem(item)
			} else if item.ItemType == "loader" {
				err = a.downloadLoaderItem(item)
			} else if item.ItemType == "modpack" {
				err = a.installModpack(item)
			} else if item.ItemType == "game+loader" {
				a.emitProgress("downloading", "下载原版游戏 "+item.ID, 0, 0)
				if err = a.DownloadVersion(item.ID, item.URL, item.ID); err != nil {
					err = fmt.Errorf("下载原版游戏失败: %v", err)
				} else {
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
				a.downloadList[idx].ErrorMsg = err.Error()
			} else {
				a.downloadList[idx].Status = "completed"
				a.downloadList[idx].Progress = 100
			}
			a.downloadMutex.Unlock()
			runtime.EventsEmit(a.ctx, "downloadListUpdated", a.GetDownloadList())
		}
	}()
	return nil
}

func (a *App) CancelDownloadList() error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	if !a.isDownloading || a.downloadCancel == nil {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	close(a.downloadCancel)
	return nil
}

// 单个 / 全部 native 条目解压后的体积上限。
// 正常的 .dll / .so / .jnilib 远小于这些值，上限只在“异常压缩包 / zip 炸弹”时触发，
// 避免一个恶意 natives jar 借超大条目或高压缩比把磁盘写满。

func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	safeName, why := SafeVersionComponent(customName)
	if why != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本下载名: "+describeNameReject(why))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(why))
	}
	customName = safeName
	// loaderName / loaderVersion 会被拼进展示名，最终也成为版本目录名，同样必须是
	// 干净单段（前端可传任意字符串，不能假设它只来自官方加载器版本列表）。
	if loaderName != "" {
		safeLoader, whyL := SafeLoaderComponent(loaderName)
		if whyL != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝非法加载器名: "+describeNameReject(whyL))
			return fmt.Errorf("加载器名称无效: %s", describeNameReject(whyL))
		}
		safeLoaderVer, whyV := SafeLoaderComponent(loaderVersion)
		if whyV != nameRejectNone {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"minecraft", "拒绝非法加载器版本: "+describeNameReject(whyV))
			return fmt.Errorf("加载器版本无效: %s", describeNameReject(whyV))
		}
		loaderName, loaderVersion = safeLoader, safeLoaderVer
	}
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}
	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}
	// 拼接后的完整名也要过长度/单段校验（customName 合法但加上 loader 后缀可能超长）。
	if finalName, whyD := SafeVersionDisplayName(displayName); whyD != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"minecraft", "拒绝非法版本展示名: "+describeNameReject(whyD))
		return fmt.Errorf("版本名称无效: %s", describeNameReject(whyD))
	} else {
		displayName = finalName
	}
	pending := DownloadItem{
		ID: versionID, URL: versionURL, CustomName: displayName, Type: versionType,
		ItemType: "game+loader", LoaderName: loaderName, LoaderVersion: loaderVersion,
		OptiFineType: optifineType, OptiFinePatch: optifinePatch, Status: "pending", Progress: 0,
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
