package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"net/http"
	"path/filepath"
)

func (a *App) GetModDependencies(versionID string) ([]ModDependencyInfo, error) {
	if !isValidModID(versionID) {
		return nil, fmt.Errorf("无效的版本 ID 格式")
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := readAPIJSON(resp, &version); err != nil {
		return nil, fmt.Errorf("解析版本详情失败: %v", err)
	}

	var deps []ModDependencyInfo
	if version.Dependencies == nil {
		return deps, nil
	}
	for _, dep := range version.Dependencies {
		if dep.ProjectID == "" {
			continue
		}

		depInfo := ModDependencyInfo{
			ProjectID:      dep.ProjectID,
			DependencyType: dep.DependencyType,
		}

		detail, err := a.GetModDetail(dep.ProjectID)
		if err == nil && detail != nil {
			depInfo.ProjectName = detail.Title
			depInfo.IconURL = detail.IconURL
		} else {
			depInfo.ProjectName = dep.ProjectID
		}

		deps = append(deps, depInfo)
	}

	return deps, nil
}

func (a *App) AddModToDownloadList(versionID string, savePath string) error {
	if !isValidModID(versionID) {
		return fmt.Errorf("无效的版本 ID 格式")
	}

	// 安全校验: savePath 若由前端指定，只能是受管 mods 目录（全局 mods 或版本隔离
	// mods）本身。旧实现只判定 PathWithin(mcDir)，渲染层可把下载的 jar 投放到
	// libraries / versions / mcDir 根等任意子目录（越权落盘）。
	if savePath != "" {
		mcDir := a.GetMinecraftDir()
		dirAbs, ok := resolveManagedModsDir(mcDir, savePath)
		if !ok {
			recordSecurityEvent(auditCategoryPermission, auditSeverityWarn, auditActionRejected,
				"AddModToDownloadList", "拒绝把 Mod 下载到受管 Mods 目录之外: "+savePath)
			return fmt.Errorf("保存路径必须是 Mods 目录")
		}
		savePath = dirAbs
	}

	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := readAPIJSON(resp, &version); err != nil {
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
		return fmt.Errorf("未找到 Mod 文件")
	}

	// 安全校验：下载 URL 必须是 HTTPS 且主机在 Mod 下载白名单内
	// （官方 Modrinth/CurseForge CDN 与 mcimirror 镜像），防止被篡改的
	// 版本元数据把下载指向任意主机。
	if err := validateModDownloadURL(primaryFile.URL); err != nil {
		return err
	}

	// 登记 Modrinth 给的哈希和期望大小，下载完会校验（并发安全，详见 modverify.go）
	modExpect.record(primaryFile.URL, *primaryFile)

	if savePath == "" {
		mcDir := a.GetMinecraftDir()
		savePath = filepath.Join(mcDir, "mods")
	}

	if err := ensurePrivateDir(savePath); err != nil {
		return fmt.Errorf("创建保存目录失败: %w", err)
	}

	// 文件名来自 Modrinth 服务器元数据，filepath.Base 只能剥目录，挡不住控制字符、
	// Windows 保留设备名、尾点与可执行扩展名；统一走 nameguard，逐级回退到合法默认名。
	customName := PickSafeModFileName(primaryFile.Filename, version.Name)

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: customName,
		Type:       "mod",
		ItemType:   "mod",
		SavePath:   savePath,
		Status:     "pending",
		Progress:   0,
		// r35：把 Modrinth 声明大小带进队列，供聚合字节预算裁决；远端未给时为 0（未知）。
		SizeBytes: primaryFile.Size,
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

// ResolveModDependencies 解析 mod 的前置依赖
