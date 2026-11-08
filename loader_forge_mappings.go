package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxMappingsDownloadBytes int64 = 1 << 30

func (a *App) ensureForgeMappings(installerPath string, mcDir string) {
	a.writeLog("===== 开始检查 Forge Mappings 文件 =====")

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
			data, err := readZipEntryLimited(f, maxInstallerJSONBytes)
			if err != nil {
				a.writeLog("读取 install_profile.json 失败(条目过大或损坏，跳过): %v", err)
				break
			}
			json.Unmarshal(data, &installProfile)

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
	if !isValidMCVersion(mcVersion) {
		a.writeLog("mcVersion 未通过版本格式白名单（跳过 Mappings 检查）: %s", mcVersion)
		return
	}

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

	clientValue = strings.Trim(clientValue, "[]")
	atIndex := strings.Index(clientValue, "@")
	if atIndex == -1 {
		a.writeLog("MOJMAPS.client 格式错误（跳过 Mappings 检查）")
		return
	}

	originalName := clientValue[:atIndex]
	extension := clientValue[atIndex+1:]

	// 坐标与扩展名来自不可信的安装器 JSON，不能再用 Split 后原样拼 filepath.Join，
	// 否则 ".." 段 / 分隔符 / 带穿越的扩展名会把 mappings 写到 libraries 之外。
	// 统一走严格白名单推导，并强制结果落在 <mcDir>/libraries 内。
	targetPath, ok := SafeMojmapsMappingsPath(mcDir, originalName, extension)
	if !ok {
		a.writeLog("MOJMAPS.client 坐标或扩展名未通过路径白名单（跳过 Mappings 检查）")
		return
	}

	a.writeLog("目标路径: %s", targetPath)

	versionDir := filepath.Join(mcDir, "versions", mcVersion)
	jsonPath := filepath.Join(versionDir, mcVersion+".json")

	var rawJSON map[string]interface{}
	if err := readLocalJSONBounded(jsonPath, &rawJSON, 0, "原版版本 JSON"); err != nil {
		a.writeLog("无法读取/解析原版版本 JSON: %v", err)
		return
	}

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

	expectedSHA1, _ := clientMappings["sha1"].(string)
	expectedSHA1 = strings.ToLower(strings.TrimSpace(expectedSHA1))

	if expectedSHA1 != "" {
		if info, statErr := os.Stat(targetPath); statErr == nil && info.Size() > 0 {
			if existingSHA1, hashErr := fileSHA1Hex(targetPath); hashErr == nil && existingSHA1 == expectedSHA1 {
				a.writeLog("Mappings 文件已存在且 SHA1 校验通过: %s", targetPath)
				return
			}
			a.writeLog("Mappings 文件已存在但 SHA1 不符，重新下载: %s", targetPath)
		}
	}

	// 安全验证：只允许 HTTPS
	if !isHTTPSURL(mappingsURL) {
		a.writeLog("跳过不安全的下载 URL（非 HTTPS）: %s", mappingsURL)
		return
	}

	mappingsURL = rewriteMappedDataURLToBMCL(mappingsURL)

	a.writeLog("使用 Go 原生 HTTP 下载 Mappings 文件...")
	a.writeLog("下载 URL: %s", mappingsURL)
	a.writeLog("保存到: %s", targetPath)

	// 这里是手写流式下载（os.OpenFile 直接落盘），由本处显式确保目录 0700 并收权。
	if err := ensurePrivateDir(filepath.Dir(targetPath)); err != nil {
		a.writeLog("创建目标目录失败: %v", err)
		return
	}

	// 安全修复：使用 Go 原生 HTTP 下载，替代 PowerShell 命令，防止命令注入
	client := safeHTTPClient()
	req, err := http.NewRequest("GET", mappingsURL, nil)
	if err != nil {
		a.writeLog("创建下载请求失败: %v", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		a.writeLog("下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.writeLog("下载失败: HTTP %d", resp.StatusCode)
		return
	}

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		a.writeLog("创建目标文件失败: %v", err)
		return
	}
	defer out.Close()

	limited := io.LimitReader(resp.Body, maxMappingsDownloadBytes+1)
	n, copyErr := io.Copy(out, limited)
	if copyErr != nil || n > maxMappingsDownloadBytes {
		a.writeLog("mappings 文件超过 %d 字节上限，中止下载", maxMappingsDownloadBytes)
		os.Remove(targetPath)
		return
	}

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

	if expectedSHA1 != "" {
		actualSHA1, hashErr := fileSHA1Hex(targetPath)
		if hashErr != nil || actualSHA1 != expectedSHA1 {
			a.writeLog("Mappings SHA1 校验失败（期望 %s，实际 %s），删除半可信文件", expectedSHA1, actualSHA1)
			os.Remove(targetPath)
			return
		}
	}

	a.writeLog("Mappings 下载成功! 文件大小: %d 字节, 路径: %s", fileInfo.Size(), targetPath)
}
