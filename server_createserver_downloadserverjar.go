package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

)

func (a *App) downloadServerJar(version string, targetDir string) error {
	jarPath := filepath.Join(targetDir, version+"-server.jar")

	// 如果已存在则跳过
	if _, err := os.Stat(jarPath); err == nil {
		return nil
	}

	// 1. 获取版本 JSON URL
	manifest, err := a.GetVersionManifest()
	if err != nil {
		return fmt.Errorf("获取版本清单失败: %v", err)
	}

	var versionURL string
	for _, v := range manifest {
		if v.ID == version {
			versionURL = v.URL
			break
		}
	}
	if versionURL == "" {
		return fmt.Errorf("找不到版本 %s", version)
	}

	// 替换为 BMCLAPI 镜像
	versionURL = strings.Replace(versionURL, "https://piston-meta.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	versionURL = strings.Replace(versionURL, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)

	// 2. 下载版本 JSON
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(versionURL)
	if err != nil {
		return fmt.Errorf("下载版本 JSON 失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var versionJSON map[string]interface{}
	if err := json.Unmarshal(body, &versionJSON); err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 3. 从 JSON 中提取 server 下载地址
	downloads, ok := versionJSON["downloads"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("版本 JSON 中没有 downloads 字段")
	}
	server, ok := downloads["server"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Mojang 没有为 %s 提供官方服务端下载", version)
	}

	jarURL, _ := server["url"].(string)
	if jarURL == "" {
		return fmt.Errorf("无法获取服务端下载地址")
	}

	// 替换为 BMCLAPI 镜像
	jarURL = strings.Replace(jarURL, "https://piston-data.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	jarURL = strings.Replace(jarURL, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)

	// 4. 下载 JAR 文件
	downloadClient := &http.Client{Timeout: 120 * time.Second}
	dlResp, err := downloadClient.Get(jarURL)
	if err != nil {
		return fmt.Errorf("下载服务端 JAR 失败: %v", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != 200 {
		return fmt.Errorf("下载服务端 JAR 失败 (HTTP %d)", dlResp.StatusCode)
	}

	file, err := os.Create(jarPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, dlResp.Body); err != nil {
		os.Remove(jarPath)
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

// StartServer 启动服务器
