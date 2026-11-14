package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

)

func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 查找版本 JSON 文件（文件名可能与文件夹名不同）
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		// 尝试查找文件夹中的任意 JSON 文件
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		} else {
			return nil, fmt.Errorf("未找到版本 JSON: %s", versionDir)
		}
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("读取版本 JSON 失败: %v", err)
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 处理 inheritsFrom
	if versionJSON.InheritsFrom != "" {
		parentJSON, err := a.resolveVersionJSON(versionJSON.InheritsFrom)
		if err != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（将继续使用当前版本信息）\n", err)
		} else {
			// 合并父版本信息
			versionJSON = a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}

	return &versionJSON, nil
}

// mergeVersionJSON 合并父版本和子版本 JSON
// 子版本（Forge/Fabric）的字段覆盖父版本（原版）的字段
