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

func (a *App) GetOptiFineVersions(mcVersion string) ([]LoaderInfo, error) {
	apiURL := "https://bmclapi2.bangbang93.com/optifine/versionList"

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 OptiFine 版本失败: HTTP %d", resp.StatusCode)
	}

	var allEntries []BMCLAPIOptiFineEntry
	if err := json.NewDecoder(resp.Body).Decode(&allEntries); err != nil {
		return nil, fmt.Errorf("解析 OptiFine 版本失败: %v", err)
	}

	loaders := []LoaderInfo{}
	for _, entry := range allEntries {
		if entry.MCVersion != mcVersion {
			continue
		}

		versionName := entry.Type + "_" + entry.Patch

		// BMCLAPI 镜像下载 URL
		downloadURL := fmt.Sprintf(
			"https://bmclapi2.bangbang93.com/optifine/%s/%s/%s",
			entry.MCVersion, entry.Type, entry.Patch,
		)

		isPreview := strings.HasPrefix(entry.Filename, "preview_")

		loaders = append(loaders, LoaderInfo{
			Name:         "optifine",
			DisplayName:  "OptiFine",
			Version:      versionName,
			MCVersion:    mcVersion,
			DownloadURL:  downloadURL,
			Stable:       !isPreview,
			IsPreview:    isPreview,
			Patch:        entry.Patch,
			OptiFineType: entry.Type,
		})
	}

	return loaders, nil
}

// ===== 加载器安装（完全按照 PCL 的逻辑） =====

// extractForgeInstaller 提取 bangbang93 ForgeInstaller 到临时目录
func (a *App) extractForgeInstaller() (string, error) {
	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	cacheDir := filepath.Join(tempDir, "qgl_cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %v", err)
	}

	installerPath := filepath.Join(cacheDir, "forge_installer.jar")

	// 如果已存在且大小正确，直接返回
	if info, err := os.Stat(installerPath); err == nil && info.Size() == int64(len(forgeInstallerJar)) {
		return installerPath, nil
	}

	// 写入文件
	if err := os.WriteFile(installerPath, forgeInstallerJar, 0644); err != nil {
		return "", fmt.Errorf("提取 ForgeInstaller 失败: %v", err)
	}

	return installerPath, nil
}

// isOldForge 判断是否为旧版 Forge（版本号 < 20，不需要运行安装器）
