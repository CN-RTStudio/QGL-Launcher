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

func getUMFSCache(cachePath string) *umfsCache {
	umfsCacheOnce.Do(func() {
		globalUMFSCache = &umfsCache{path: cachePath, data: map[string]string{}}
		// 缓存是本地文本 JSON，走有界读取（默认 64MiB）：文件缺失 / 损坏 / 被改成
		// 超大体积都从空缓存起步，绝不整体读进内存，也不阻断后续下载。
		if err := readLocalJSONBounded(cachePath, &globalUMFSCache.data, 0, "umfs完整性缓存"); err != nil {
			globalUMFSCache.data = map[string]string{}
		}
	})
	return globalUMFSCache
}

func (c *umfsCache) keyFor(hashes map[string]string) string {
	if v := strings.ToLower(strings.TrimSpace(hashes["sha512"])); v != "" {
		return "sha512:" + v
	}
	if v := strings.ToLower(strings.TrimSpace(hashes["sha1"])); v != "" {
		return "sha1:" + v
	}
	return ""
}

func (c *umfsCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok
}

func (c *umfsCache) set(key, umfsHex string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = umfsHex
	// 原子私有写（含 0700 目录收敛、0600、fsync/rename、拒符号链接），替换原先
	// 裸 Marshal+MkdirAll+WriteFile；失败仅表示本次指纹未持久化，不影响当次校验结果。
	_ = writePrivateJSON(c.path, c.data)
}
