package main

import (
	"archive/zip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

)

func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

	// 1. 从 install_profile.json 获取配置
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		a.writeLog("无法打开安装器（跳过 Mappings 检查）: %v", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	var mcVersion string
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()

			json.Unmarshal(data, &installProfile)

			// 获取 mcVersion - 新版 Forge 中 minecraft 是字符串格式 "1.19.2"
			if minecraftVal, ok := installProfile["minecraft"]; ok {
				if mv, ok := minecraftVal.(string); ok {
					mcVersion = mv
					a.writeLog("找到 mcVersion: %s", mcVersion)
				}
			}
			break
		}
	}

	if installProfile == nil || mcVersion == "" {
		a.writeLog("未找到 mcVersion（跳过 Mappings 检查）")
		return
	}

	// 2. 检查是否需要 MOJMAPS
	dataSection, ok := installProfile["data"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 data 字段（跳过 Mappings 检查）")
		return
	}

	mojmapsData, ok := dataSection["MOJMAPS"].(map[string]interface{})
	if !ok {
		a.writeLog("未找到 MOJMAPS 字段（跳过 Mappings 检查）")
		return
	}

	clientValue, ok := mojmapsData["client"].(string)
	if !ok || clientValue == "" {
		a.writeLog("未找到 MOJMAPS.client 字段（跳过 Mappings 检查）")
		return
	}

	// 解析 MOJMAPS.client: [net.minecraft:client:1.19.2-20220805.130853:mappings@txt]
	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	parts := strings.Split(originalName, ":")
	if len(parts) < 3 {
		a.writeLog("MOJMAPS.client Maven 格式错误（跳过 Mappings 检查）")
		return
	}

	groupPath := strings.Replace(parts[0], ".", "/", -1)
	artifact := parts[1]
	versionPart := parts[2]

	targetPath := filepath.Join(mcDir, "libraries", groupPath, artifact, versionPart,
		fmt.Sprintf("%s-%s-mappings.%s", artifact, versionPart, extension))

	a.writeLog("目标路径: %s", targetPath)

	// 检查是否已存在
	if _, err := os.Stat(targetPath); err == nil {
		a.writeLog("Mappings 文件已存在: %s", targetPath)
		return
	}

	// 3. 从原版版本 JSON 获取 client_mappings URL
	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		a.writeLog("无法读取原版版本 JSON: %v", err)
		return
	}

	var rawJSON map[string]interface{}
	json.Unmarshal(jsonData, &rawJSON)

	downloads, _ := rawJSON["downloads"].(map[string]interface{})
	if downloads == nil {
		a.writeLog("未找到 downloads 字段")
		return
	}

	clientMappings, _ := downloads["client_mappings"].(map[string]interface{})
	if clientMappings == nil {
		a.writeLog("未找到 client_mappings 字段")
		return
	}

	mappingsURL, _ := clientMappings["url"].(string)
	if mappingsURL == "" {
		a.writeLog("未找到 client_mappings URL")
		return
	}

	// 替换为 BMCLAPI 镜像
	mappingsURL = strings.Replace(mappingsURL, "https://piston-data.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	mappingsURL = strings.Replace(mappingsURL, "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)

	a.writeLog("使用 CMD 命令下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 4. 创建目标目录
	os.MkdirAll(filepath.Dir(targetPath), 0755)

	// 5. 使用 PowerShell Invoke-WebRequest 下载文件（带 User-Agent 避免被拦截）
	a.writeLog("执行下载命令...")
	downloadCmd := exec.Command("powershell", "-Command",
		fmt.Sprintf("[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $headers = @{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1'}; Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing -Headers $headers",
			mappingsURL, targetPath))
	downloadCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := downloadCmd.CombinedOutput()

	if err != nil {
		a.writeLog("CMD 下载失败: %v, 输出: %s", err, string(output))
		return
	}

	// 6. 验证文件是否存在且不为空
	fileInfo, statErr := os.Stat(targetPath)
	if statErr != nil {
		a.writeLog("下载后验证文件失败: %v", statErr)
		return
	}

	if fileInfo.Size() == 0 {
		a.writeLog("下载的文件为空！删除空文件")
		os.Remove(targetPath)
		return
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}

// downloadForgeMappings 下载 Forge 新版所需的 client_mappings 文件（保留旧函数以保持兼容性）
// Forge 安装器期望的路径格式: libraries/net/minecraft/client/{mcpVersion}/client-{mcpVersion}-mappings.txt
