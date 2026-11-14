package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) GetInstalledVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}

	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		// 验证版本是否完整安装
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}

		info := a.readVersionInfo(versionFolder, entry.Name())
		installed = append(installed, info)
	}

	return installed, nil
}

// ScanVersions 扫描所有版本文件夹，创建/更新 QGL/config.json，返回最新列表
func (a *App) ScanVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}

	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}

		info := a.scanVersionFolder(versionFolder, entry.Name())
		installed = append(installed, info)
	}

	return installed, nil
}

// InstalledVersionInfo 安装版本的信息
type InstalledVersionInfo struct {
	FolderName string `json:"folderName"` // 文件夹名（用于启动）
	Name       string `json:"name"`       // 显示名（可能为空）
	Version    string `json:"version"`    // 游戏版本（如 1.12.2）
	Loader     string `json:"loader"`     // 加载器（forge/fabric/neoforge，可能为空）
	Type       string `json:"type"`       // 类型：game/loader/modpack
}

// readVersionInfo 仅读取 QGL/config.json，没有则返回基本信息（不创建）
func (a *App) readVersionInfo(versionFolder string, folderName string) InstalledVersionInfo {
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName,
				Name:       config["name"],
				Version:    config["version"],
				Loader:     config["loader"],
				Type:       config["type"],
			}
		}
	}
	// 没有 config.json，返回基本信息
	return InstalledVersionInfo{
		FolderName: folderName,
		Name:       "",
		Version:    folderName,
		Loader:     "",
		Type:       "game",
	}
}

// scanVersionFolder 扫描版本文件夹，解析版本 JSON，创建/更新 QGL/config.json
func (a *App) scanVersionFolder(versionFolder string, folderName string) InstalledVersionInfo {
	// 1. 尝试读取已有的 QGL/config.json
	configPath := filepath.Join(versionFolder, "QGL", "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]string
		if err := json.Unmarshal(data, &config); err == nil {
			return InstalledVersionInfo{
				FolderName: folderName,
				Name:       config["name"],
				Version:    config["version"],
				Loader:     config["loader"],
				Type:       config["type"],
			}
		}
	}

	// 2. 没有 config.json，解析版本 JSON 创建
	versionJSON, err := a.resolveVersionJSON(folderName)
	if err != nil {
		// 解析失败，返回基本信息
		return InstalledVersionInfo{
			FolderName: folderName,
			Name:       "",
			Version:    folderName,
			Loader:     "",
			Type:       "game",
		}
	}

	// 读取原始 JSON 文本用于检测 loader
	jsonPath := filepath.Join(versionFolder, folderName+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		jsonFiles, _ := filepath.Glob(filepath.Join(versionFolder, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		}
	}
	jsonText, _ := os.ReadFile(jsonPath)

	// 检测 loader（参考 PCL ModMinecraft.vb）
	loader := ""
	if strings.Contains(string(jsonText), "net.fabricmc:fabric-loader") {
		loader = "fabric"
	} else if strings.Contains(string(jsonText), "org.quiltmc:quilt-loader") {
		loader = "quilt"
	} else if strings.Contains(string(jsonText), "net.neoforge") {
		loader = "neoforge"
	} else if strings.Contains(string(jsonText), "minecraftforge") && !strings.Contains(string(jsonText), "net.neoforge") {
		loader = "forge"
	}

	// 确定游戏版本
	gameVersion := versionJSON.InheritsFrom
	if gameVersion == "" {
		gameVersion = versionJSON.ID
	}

	// 确定类型
	versionType := "game"
	if loader != "" {
		versionType = "loader"
	}

	info := InstalledVersionInfo{
		FolderName: folderName,
		Name:       "",
		Version:    gameVersion,
		Loader:     loader,
		Type:       versionType,
	}

	// 3. 创建 QGL/config.json
	configDir := filepath.Join(versionFolder, "QGL")
	if err := os.MkdirAll(configDir, 0755); err == nil {
		config := map[string]string{
			"type":    versionType,
			"name":    "",
			"version": gameVersion,
			"loader":  loader,
		}
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0644)
	}

	return info
}

// ===== 下载列表功能 =====

// AddToDownloadList 添加版本到下载列表
func (a *App) AddToDownloadList(versionID string, versionURL string, customName string, versionType string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         versionID,
		URL:        versionURL,
		CustomName: customName,
		Type:       versionType,
		ItemType:   "game",
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddToDownloadListWithLoader 添加带加载器的游戏到下载列表
func (a *App) AddToDownloadListWithLoader(versionID string, versionURL string, customName string, versionType string, loaderName string, loaderVersion string, optifineType string, optifinePatch string) error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在同名版本: %s", customName)
		}
	}

	displayName := customName
	if loaderName != "" {
		displayName += " (" + loaderName + " " + loaderVersion + ")"
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:             versionID,
		URL:            versionURL,
		CustomName:     displayName,
		Type:           versionType,
		ItemType:       "game+loader",
		LoaderName:     loaderName,
		LoaderVersion:  loaderVersion,
		OptiFineType:   optifineType,
		OptiFinePatch:  optifinePatch,
		Status:         "pending",
		Progress:       0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// AddJavaToDownloadList 添加 Java 到下载列表
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

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	customName := "Java " + fmt.Sprintf("%d", majorVer)
	for _, item := range a.downloadList {
		if item.CustomName == customName {
			return fmt.Errorf("下载列表中已存在: %s", customName)
		}
	}

	a.downloadList = append(a.downloadList, DownloadItem{
		ID:         fmt.Sprintf("java-%d", majorVer),
		URL:        target.URL,
		CustomName: customName,
		Type:       "java",
		ItemType:   "java",
		JavaMajor:  majorVer,
		Status:     "pending",
		Progress:   0,
	})

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}

// RemoveFromDownloadList 从下载列表移除
