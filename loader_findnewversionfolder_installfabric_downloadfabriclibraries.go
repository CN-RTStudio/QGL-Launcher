package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

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
