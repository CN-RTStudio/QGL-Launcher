package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

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
