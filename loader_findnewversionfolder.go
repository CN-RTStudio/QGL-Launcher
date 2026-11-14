package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

)



func (a *App) findNewVersionFolder(mcDir string, oldVersions map[string]bool, mcVersion string, loaderType string) string {
	versionsDir := filepath.Join(mcDir, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return ""
	}

	// 优先查找新增的文件夹
	for _, entry := range entries {
		if !entry.IsDir() || oldVersions[entry.Name()] {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		// 检查是否包含加载器类型和 MC 版本
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	// 如果没有找到新增的，查找所有匹配的文件夹
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, loaderType) && strings.Contains(nameLower, strings.ToLower(mcVersion)) {
			versionFolder := filepath.Join(versionsDir, name)
			if a.validateVersionInstallation(versionFolder) {
				return versionFolder
			}
		}
	}

	return ""
}

// InstallFabric 安装 Fabric（直接下载 profile JSON + 预下载库文件）
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
func (a *App) downloadFabricLibraries(profileJSON map[string]interface{}, mcDir string) {
	libsDir := filepath.Join(mcDir, "libraries")

	// 从 profileJSON 的 libraries 数组中提取需要下载的库
	libs, ok := profileJSON["libraries"].([]interface{})
	if !ok {
		fmt.Printf("Fabric profile JSON 中没有 libraries 字段\n")
		return
	}

	downloadedCount := 0
	// 先收集需要下载的库，再带计数进度下载
	type fabLibTask struct {
		url  string
		path string
	}
	var fabTasks []fabLibTask
	for _, libRaw := range libs {
		libMap, ok := libRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// 获取 downloads.artifact 信息
		downloads, ok := libMap["downloads"].(map[string]interface{})
		if !ok {
			continue
		}

		artifact, ok := downloads["artifact"].(map[string]interface{})
		if !ok {
			continue
		}

		url, _ := artifact["url"].(string)
		path, _ := artifact["path"].(string)
		if url == "" || path == "" {
			continue
		}

		// 替换为 BMCLAPI 镜像（覆盖所有已知的 Maven 仓库）
		url = strings.Replace(url, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1)

		destPath := filepath.Join(libsDir, path)

		// 已存在则跳过
		if _, err := os.Stat(destPath); err == nil {
			continue
		}

		fabTasks = append(fabTasks, fabLibTask{url: url, path: destPath})
	}

	for i, task := range fabTasks {
		a.emitProgress("downloading", fmt.Sprintf("Fabric 库文件 %d/%d", i+1, len(fabTasks)), int64(i+1), int64(len(fabTasks)))
		os.MkdirAll(filepath.Dir(task.path), 0755)
		if err := a.downloadFile(task.url, task.path, false); err != nil {
			fmt.Printf("下载 Fabric 库失败: %v\n", err)
		} else {
			downloadedCount++
		}
	}

	if downloadedCount > 0 {
		fmt.Printf("Fabric 库文件预下载完成: 成功下载 %d 个\n", downloadedCount)
	}
}

// InstallNeoForge 安装 NeoForge（使用 bangbang93 ForgeInstaller）
