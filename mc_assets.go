package main

import (
	"os"
	"path/filepath"
)

func (a *App) fixAssetsIndex(mcDir string, versionJSON *VersionJSON) {
	if versionJSON.AssetIndex == nil || versionJSON.AssetIndex.URL == "" {
		return
	}
	// AssetIndex.ID 来自不可信版本 JSON，会拼成 indexes/<id>.json 落盘路径，
	// 必须和 DownloadVersion 主路径一样过单段安全名校验，拒绝 "../" 等穿越名。
	safeID := SafeSimpleName(versionJSON.AssetIndex.ID)
	if safeID == "" {
		a.writeLog("资源索引 ID 不安全，拒绝补全: %q", versionJSON.AssetIndex.ID)
		recordSecurityEvent("asset", "high", "reject-asset-index-id", "fixAssetsIndex", versionJSON.AssetIndex.ID)
		return
	}
	assetIndexDir := filepath.Join(mcDir, "assets", "indexes")
	assetIndexPath := filepath.Join(assetIndexDir, safeID+".json")
	if inspectRegularFile(assetIndexPath).trustable() {
		return
	}
	a.writeLog("资源索引文件缺失，正在下载: %s", safeID)
	// 目标目录由 downloadFromMirrors→downloadFileBounded 统一以 0700 创建/收权，无需预建。
	urls := a.getMirrorURLs(versionJSON.AssetIndex.URL)
	for i, u := range urls {
		urls[i] = rewriteMetaIndexURLToBMCL(u)
	}
	if a.downloadFromMirrors(urls, assetIndexPath, maxMetadataJSONBytes) {
		a.writeLog("资源索引文件下载完成: %s", safeID)
		a.fixMissingAssets(mcDir, assetIndexPath)
	} else {
		a.writeLog("资源索引文件下载失败: %s", safeID)
	}
}

func (a *App) downloadAssetObject(urls []string, objPath string, expectedHash string) bool {
	if !a.downloadFromMirrors(urls, objPath, maxAssetObjectBytes) {
		return false
	}
	if a.checkFileHash(objPath, expectedHash) {
		return true
	}
	os.Remove(objPath)
	removeCachedFileMeta(objPath)
	a.writeLog("资源对象 SHA1 校验失败，已删除: %s", expectedHash)
	return false
}
