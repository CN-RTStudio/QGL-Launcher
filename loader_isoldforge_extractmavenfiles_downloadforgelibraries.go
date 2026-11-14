package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	// 读取 install_profile.json 和 version.json
	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &profileData)
		}
		if f.Name == "version.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &versionData)
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	// 合并两个 JSON 的 libraries
	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	// 下载每个支持库（先收集任务再带计数进度下载）
	libsDir := filepath.Join(mcDir, "libraries")
	type libDlTask struct {
		url  string
		path string
		name string
	}
	var libTasks []libDlTask
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
		if !ok {
			continue
		}

		// 获取下载信息
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

		// 替换为 BMCLAPI 镜像
		url = strings.Replace(url, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1)
		url = strings.Replace(url, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)

		destPath, pathOK := archiveEntryPathInside(libsDir, path)
		if !pathOK {
			a.recordSecurityEventBlockedArchive("downloadForgeLibraries", libsDir, path)
			continue
		}
		if _, err := os.Stat(destPath); err == nil {
			continue // 已存在
		}

		libTasks = append(libTasks, libDlTask{url: url, path: destPath, name: filepath.Base(path)})
	}

	for i, task := range libTasks {
		a.emitProgress("downloading", fmt.Sprintf("支持库 %d/%d: %s", i+1, len(libTasks), task.name), int64(i+1), int64(len(libTasks)))
		if err := a.downloadFile(task.url, task.path, false); err != nil {
			fmt.Printf("下载支持库失败 %s: %v\n", task.name, err)
		}
	}

	// === 新版 Forge 需要 Mappings 文件（参考 PCL 的 DlClientFix） ===
	// install_profile.json 中的 data.MOJMAPS 字段引用了原版 MC 的 client_mappings
	dataSection, hasData := profileData["data"].(map[string]interface{})
	if !hasData {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
	} else if _, hasMojmaps := dataSection["MOJMAPS"]; hasMojmaps {
		fmt.Printf("检测到新版 Forge，需要下载 Mappings 文件\n")
		a.downloadForgeMappings(mcDir, mcVersion, installerPath)
	} else {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
	}

	return nil
}

// ensureForgeMappings 确保 Forge 新版需要的 Mappings 文件存在
// 使用 CMD 命令（Invoke-WebRequest）下载文件
