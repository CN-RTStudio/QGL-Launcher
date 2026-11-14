package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

)

func (a *App) InstallFabric(mcVersion string, loaderVersion string) error {
	mcDir := a.GetMinecraftDir()

	// Fabric 阶段划分：profile 获取 + JSON 写入 0-15%，库文件 15-95%，验证 95-100%
	a.setProgressScale(0, 15)

	// 1. 获取 Fabric profile JSON（BMCLAPI 镜像）
	profileURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/fabric-meta/v2/versions/loader/%s/%s/profile/json",
		mcVersion, loaderVersion,
	)

	a.emitProgress("downloading", "获取 Fabric profile", 0, 0)

	resp, err := http.Get(profileURL)
	if err != nil {
		return fmt.Errorf("获取 Fabric profile 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 Fabric profile 失败: HTTP %d", resp.StatusCode)
	}

	var profileJSON map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&profileJSON); err != nil {
		return fmt.Errorf("解析 Fabric profile 失败: %v", err)
	}

	// 2. 设置版本 ID
	versionID := fmt.Sprintf("fabric-loader-%s-%s", loaderVersion, mcVersion)
	profileJSON["id"] = versionID

	// 3. 创建版本文件夹
	versionDir := filepath.Join(mcDir, "versions", versionID)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	// 4. 保存版本 JSON
	jsonData, err := json.MarshalIndent(profileJSON, "", "  ")
	if err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("序列化 JSON 失败: %v", err)
	}

	jsonPath := filepath.Join(versionDir, versionID+".json")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("保存版本 JSON 失败: %v", err)
	}

	// Fabric 阶段划分：profile 获取 + JSON 写入 0-15%，库文件 15-95%，验证 95-100%
	a.setProgressScale(15, 95)
	a.emitProgress("downloading", "下载 Fabric 库文件", 0, 0)
	a.downloadFabricLibraries(profileJSON, mcDir)
	a.setProgressScale(95, 100)

	// 6. 验证安装
	if !a.validateVersionInstallation(versionDir) {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("Fabric 安装验证失败")
	}

	return nil
}

// downloadFabricLibraries 下载 Fabric 版本 JSON 中引用的所有库文件
