package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

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
