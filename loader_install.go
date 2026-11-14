package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func (a *App) InstallFabric(mcVersion string, loaderVersion string) error {
	if !isValidMCVersion(mcVersion) {
		return fmt.Errorf("无效的 Minecraft 版本格式")
	}
	if !isSafeFileName(loaderVersion) {
		return fmt.Errorf("无效的 Fabric Loader 版本格式")
	}

	mcDir := a.GetMinecraftDir()

	profileURL := fmt.Sprintf(
		"https://bmclapi2.bangbang93.com/fabric-meta/v2/versions/loader/%s/%s/profile/json",
		mcVersion, loaderVersion,
	)

	a.emitProgress("downloading", "获取 Fabric profile", 0, 0)

	client := safeHTTPClient()
	resp, err := client.Get(profileURL)
	if err != nil {
		return fmt.Errorf("获取 Fabric profile 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 Fabric profile 失败: HTTP %d", resp.StatusCode)
	}

	var profileJSON map[string]interface{}
	if err := readAPIJSON(resp, &profileJSON); err != nil {
		return fmt.Errorf("解析 Fabric profile 失败: %v", err)
	}

	versionID := fmt.Sprintf("fabric-loader-%s-%s", loaderVersion, mcVersion)
	profileJSON["id"] = versionID

	versionDir := filepath.Join(mcDir, "versions", versionID)
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		return fmt.Errorf("创建版本目录失败: %v", err)
	}

	jsonPath := filepath.Join(versionDir, versionID+".json")
	// 有界原子私有写：Marshal/超量/落盘任一失败都清理半成品并返回，不再原地截断写。
	if err := writePrivateJSON(jsonPath, profileJSON); err != nil {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("保存版本 JSON 失败: %w", err)
	}

	a.emitProgress("downloading", "下载 Fabric 库文件", 0, 0)
	a.downloadFabricLibraries(profileJSON, mcDir)

	if !a.validateVersionInstallation(versionDir) {
		a.cleanupFailedInstallation(mcDir, versionID)
		return fmt.Errorf("Fabric 安装验证失败")
	}

	return nil
}
