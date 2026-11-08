package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) downloadForgeMappings(mcDir string, mcVersion string, installerPath string) {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		fmt.Printf("无法打开安装器（跳过 Mappings 下载）: %v\n", err)
		return
	}
	defer r.Close()

	var installProfile map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" {
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("读取 install_profile.json 失败(条目过大或损坏，跳过): %v\n", err)
				break
			}
			json.Unmarshal(data, &installProfile)
			break
		}
	}

	if installProfile == nil {
		fmt.Printf("未找到 install_profile.json（跳过 Mappings 下载）\n")
		return
	}

	if !isValidMCVersion(mcVersion) {
		fmt.Printf("mcVersion 未通过版本格式白名单（跳过 Mappings 下载）: %s\n", mcVersion)
		return
	}

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

	targetPath, ok := SafeMappingsVersionPath(mcDir, mcpVersion)
	if !ok {
		fmt.Printf("MOJMAPS.version 未通过落盘路径白名单（跳过 Mappings 下载）: %s\n", mcpVersion)
		return
	}

	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Mappings 文件已存在: %s\n", targetPath)
		return
	}

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		fmt.Printf("无法读取/解析原版版本 JSON（跳过 Mappings 下载）: %v\n", err)
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

	if !isHTTPSURL(mappingsURL) {
		fmt.Printf("跳过不安全的下载 URL（非 HTTPS）: %s\n", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	tempPath := targetPath + ".tmp"
	_ = os.Remove(tempPath)
	fmt.Printf("下载 Forge Mappings (%s): %s\n", mcpVersion, mappingsURL)
	if err := a.downloadFileBounded(mappingsURL, tempPath, false, maxMappingsDownloadBytes); err != nil {
		os.Remove(tempPath)
		fmt.Printf("下载 Mappings 失败: %v\n", err)
		return
	}

	expectedSHA1, _ := clientMappings["sha1"].(string)
	expectedSHA1 = strings.ToLower(strings.TrimSpace(expectedSHA1))
	if expectedSHA1 != "" {
		actualSHA1, hashErr := fileSHA1Hex(tempPath)
		if hashErr != nil || actualSHA1 != expectedSHA1 {
			fmt.Printf("Mappings SHA1 校验失败（期望 %s，实际 %s），删除下载文件\n", expectedSHA1, actualSHA1)
			os.Remove(tempPath)
			return
		}
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		os.Remove(tempPath)
		fmt.Printf("重命名 Mappings 文件失败: %v\n", err)
		return
	}

	fmt.Printf("Mappings 下载成功: %s\n", targetPath)
}

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		// launcher_profiles.json 是启动器状态文件，有界原子私有写防半截写与符号链接写穿；
		// 序列化错误也不再被丢弃。
		if err := writePrivateJSON(profilesPath, profiles); err != nil {
			fmt.Printf("创建 launcher_profiles.json 失败: %v\n", err)
		}
	}
}
