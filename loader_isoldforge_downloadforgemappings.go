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

func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	// 1. 从 install_profile.json 获取 MOJMAPS 配置
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	// 2. 获取 MOJMAPS 数据（包含 mcpVersion）
	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 data 字段（跳过 Mappings 下载）\n")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 MOJMAPS 字段（跳过 Mappings 下载）\n")
		return
	}

	mcpVersion, ok := mojmapsData["version"].(string)
	if !ok || mcpVersion == "" {
		fmt.Printf("未找到 MOJMAPS.version 字段（跳过 Mappings 下载）\n")
		return
	}

	fmt.Printf("检测到 Forge MOJMAPS: %s\n", mcpVersion)

	// 3. 构建目标路径
	// Forge 安装器期望的路径: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
	targetPath := filepath.Join(mcDir, "libraries", "net", "minecraft", "client", mcpVersion, fmt.Sprintf("client-%s-mappings.txt", mcpVersion))

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	// 4. 尝试从原版版本 JSON 获取 client_mappings 下载信息
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("无法读取原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
		return
	}

	var rawJSON map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawJSON); err != nil {
		fmt.Printf("解析原版版本 JSON 失败（跳过 Mappings 下载）: %v\n", err)
		return
	}

	downloads, ok := rawJSON["downloads"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 downloads 字段（跳过 Mappings 下载）\n")
		return
	}

	clientMappings, ok := downloads["client_mappings"].(map[string]interface{})
	if !ok {
		fmt.Printf("未找到 client_mappings 字段（跳过 Mappings 下载）\n")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		fmt.Printf("未找到 client_mappings URL（跳过 Mappings 下载）\n")
		return
	}

	// 5. 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	// 6. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 7. 下载文件（先下载为临时文件，然后重命名）
	tempPath := targetPath + ".tmp"
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFile(mappingsURL, tempPath, false); err != nil {
		// 如果临时文件已存在，删除它
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	// 8. 重命名为 Forge 安装器期望的名称
	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

// ensureLauncherProfiles 确保 launcher_profiles.json 存在（Forge 安装器需要）
