package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) downloadModItem(item *DownloadItem) error {
	destDir := item.SavePath
	if destDir == "" {
		mcDir := a.GetMinecraftDir()
		destDir = filepath.Join(mcDir, "mods")
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %v", err)
	}

	fileName := item.CustomName
	if fileName == "" {
		fileName = filepath.Base(item.URL)
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".jar") {
		fileName += ".jar"
	}

	destPath := filepath.Join(destDir, fileName)

	if _, err := os.Stat(destPath); err == nil {
		return nil
	}

	// 多线程分段下载（先镜像源，失败回退官方源）
	if err := a.downloadFileMultiThread(mirrorModURL(item.URL), destPath, 8); err != nil {
		a.writeLog("Mod 镜像下载失败 [%s]: %v，尝试官方源", item.URL, err)
		os.Remove(destPath)
		if err2 := a.downloadFileMultiThread(item.URL, destPath, 8); err2 != nil {
			return fmt.Errorf("下载 Mod 失败: %v", err2)
		}
	}

	return nil
}

// GetModrinthCategories 获取 Modrinth 分类标签
func (a *App) GetModrinthCategories() ([]ModCategory, error) {
	apiURL := fmt.Sprintf("%s/tag/category", modrinthBaseURL)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取分类失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取分类失败: HTTP %d", resp.StatusCode)
	}

	var categories []ModCategory
	if err := json.NewDecoder(resp.Body).Decode(&categories); err != nil {
		return nil, fmt.Errorf("解析分类失败: %v", err)
	}

	modCategories := []ModCategory{}
	for _, cat := range categories {
		if cat.ProjectType == "mod" {
			modCategories = append(modCategories, cat)
		}
	}

	return modCategories, nil
}
