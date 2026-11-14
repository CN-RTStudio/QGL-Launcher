package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

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
