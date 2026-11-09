package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

func (a *App) downloadForgeLibraries(installerPath string, mcDir string, mcVersion string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return fmt.Errorf("打开安装器失败: %v", err)
	}
	defer r.Close()

	var profileData, versionData map[string]interface{}
	for _, f := range r.File {
		if f.Name == "install_profile.json" || f.Name == "version.json" {
			// 安装器 JSON 不受信任，限 16 MiB 防解压炸弹；超限/损坏就跳过该文件。
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				fmt.Printf("跳过安装器条目 %s: %v\n", f.Name, err)
				continue
			}
			var target map[string]interface{}
			if err := json.Unmarshal(data, &target); err != nil {
				continue
			}
			if f.Name == "install_profile.json" {
				profileData = target
			} else {
				versionData = target
			}
		}
	}

	if profileData == nil {
		return fmt.Errorf("未找到 install_profile.json")
	}

	var allLibs []interface{}
	if libs, ok := profileData["libraries"].([]interface{}); ok {
		allLibs = append(allLibs, libs...)
	}
	if versionData != nil {
		if libs, ok := versionData["libraries"].([]interface{}); ok {
			allLibs = append(allLibs, libs...)
		}
	}

	libsDir := filepath.Join(mcDir, "libraries")
	for _, lib := range allLibs {
		libMap, ok := lib.(map[string]interface{})
		if !ok {
			continue
		}

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
		sha1, _ := artifact["sha1"].(string)
		if url == "" || path == "" {
			continue
		}

		// 安装器不可信：库 URL 必须落在官方/可信 Maven 主机白名单内，
		// 否则攻击者可借安装器把任意 jar 拉进 classpath（供应链 RCE）。
		if !isAllowedMavenLibURL(url) {
			fmt.Printf("跳过非可信 Maven 主机的库（防止供应链投毒）: %s\n", url)
			continue
		}

		url = rewriteMavenLibURLToBMCL(url)

		// Zip Slip 防护：库路径走严格 Maven 相对路径白名单
		safePath := SafeMavenRelPath(path)
		if safePath == "" {
			fmt.Printf("跳过不安全的库路径: %s\n", path)
			continue
		}
		destPath := filepath.Join(libsDir, filepath.FromSlash(safePath))

		// 走带官方 sha1 的下载：已存在的库也会经侧车摘要链复核，
		// 避免“文件在就直接信任”导致被替换的 jar 被加载。
		// 个别安装器确实缺 sha1 字段时仍下载（主机已白名单），但不再自行跳过校验。
		if err := a.downloadVerifiedFile(url, destPath, strings.TrimSpace(sha1), false); err != nil {
			fmt.Printf("下载/校验支持库失败 %s: %v\n", path, err)
		}
	}

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
// 安全修复：移除 PowerShell 命令，改用 Go 原生 HTTP 下载，防止命令注入
// maxMappingsDownloadBytes 限制 Forge mappings 下载体积为 1 GiB，正常映射文件只有十几 MB，只有明显炸磁盘的响应才会触发。
