package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) AddModToDownloadList(versionID string, savePath string) error {
	apiURL := fmt.Sprintf("%s/version/%s", modrinthBaseURL, versionID)

	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("获取版本详情失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取版本详情失败: HTTP %d", resp.StatusCode)
	}

	var version ModVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
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

	if savePath == "" {
		mcDir := a.GetMinecraftDir()
		savePath = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(savePath, 0755); err != nil {
		return fmt.Errorf("创建保存目录失败: %v", err)
	}

	customName := primaryFile.Filename
	if customName == "" {
		customName = version.Name
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        primaryFile.URL,
		CustomName: customName,
		Type:       "mod",
		ItemType:   "mod",
		SavePath:   savePath,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// ResolveModDependencies 解析 mod 的前置依赖，返回需要安装的依赖 mod 列表
// 递归解析依赖，跳过已选择的 mod 和可选依赖
// gameVersion 和 loader 用于筛选兼容的依赖版本
