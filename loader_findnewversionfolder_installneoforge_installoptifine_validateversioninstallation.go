package main

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) validateVersionInstallation(versionFolder string) bool {
	// 检查版本文件夹是否存在
	if _, err := os.Stat(versionFolder); os.IsNotExist(err) {
		return false
	}

	// 检查版本 JSON 文件是否存在
	jsonFiles, err := filepath.Glob(filepath.Join(versionFolder, "*.json"))
	if err != nil || len(jsonFiles) == 0 {
		return false
	}

	// 检查 JSON 文件是否有效
	for _, jsonFile := range jsonFiles {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			continue
		}

		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			continue
		}

		// 检查必要字段
		if jsonData["id"] == nil || jsonData["mainClass"] == nil {
			continue
		}

		// JSON 有效
		return true
	}

	return false
}

// cleanupFailedInstallation 清理安装失败的版本
