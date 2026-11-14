package main

import (
	"os"
	"path/filepath"
	"strings"

)

func (a *App) fixAssetsIndex(mcDir string, versionJSON *VersionJSON) {
	if versionJSON.AssetIndex == nil || versionJSON.AssetIndex.URL == "" {
		return
	}

	// 资源索引文件路径
	assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
	assetIndexPath := filepath.Join(assetIndexDir, versionJSON.AssetIndex.ID+".json")

	// 检查索引文件是否存在
	if _, err := os.Stat(assetIndexPath); err == nil {
		// 索引文件已存在，仍需校验资源本体完整性（参考 PCL：每次启动都会跑一遍资源校验）
		// 之前索引存在就直接 return，导致下载不完整的资源永远不会被补全
		a.fixMissingAssets(mcDir, assetIndexPath)
		return
	}

	a.writeLog("资源索引文件缺失，正在下载: %s", versionJSON.AssetIndex.ID)

	os.MkdirAll(assetIndexDir, 0755)

	url := versionJSON.AssetIndex.URL
	urls := a.getMirrorURLs(url)
	// 替换特殊路径
	for i, u := range urls {
		urls[i] = strings.Replace(u, "https://piston-meta.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
		urls[i] = strings.Replace(urls[i], "https://launcher.mojang.com/", "https://bmclapi2.bangbang93.com/", 1)
	}

	if a.downloadFromMirrors(urls, assetIndexPath) {
		a.writeLog("资源索引文件下载完成: %s", versionJSON.AssetIndex.ID)

		// 解析索引文件，补全缺失的资源文件（参考 PCL 的 McAssetsFixList）
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", versionJSON.AssetIndex.ID)
	}
}

// fixMissingAssets 补全缺失的资源文件（参考 PCL 的 McAssetsFixList）
