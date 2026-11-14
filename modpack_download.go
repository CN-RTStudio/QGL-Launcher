package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
)

func (a *App) AddModpackToDownloadList(versionID string, customName string) error {
	if !isValidModID(versionID) {
		return fmt.Errorf("无效的版本 ID 格式")
	}
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取整合包版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取整合包版本详情失败: HTTP %d", resp.StatusCode)
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
		return fmt.Errorf("未找到整合包文件")
	}

	if !isHTTPSURL(primaryFile.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	// 展示名优先用前端传入的 customName，其次服务端文件名 / 版本名；无论哪个来源都可能
	// 带控制字符或保留设备名，统一走严格版本名内核，全部不可信时回退固定安全名。
	displayName := ""
	for _, cand := range []string{customName, primaryFile.Filename, version.Name} {
		base := filepath.Base(strings.TrimSpace(cand))
		if clean, why := SafeVersionComponent(base); why == nameRejectNone {
			displayName = clean
			break
		}
	}
	if displayName == "" {
		displayName = "modpack"
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: displayName,
		Type:       "modpack",
		ItemType:   "modpack",
		Status:     "pending",
		Progress:   0,
		// r35：整合包 .mrpack 声明大小进入聚合预算；解压后更大但单文件与 mrpack
		// 清单本身另有 maxMrpack* 上限，这里只统计可直接获知的下载字节。
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

// installModpack 安装整合包

type umfsCache struct {
	mu   sync.Mutex
	path string
	data map[string]string
}

var globalUMFSCache *umfsCache
var umfsCacheOnce sync.Once
