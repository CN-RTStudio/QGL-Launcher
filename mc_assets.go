package main

import (
	"encoding/json"
	"fmt"
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

func (a *App) fixMissingAssets(mcDir string, assetIndexPath string) {
	data, err := readBoundedFile(assetIndexPath, maxMetadataJSONBytes)
	if err != nil {
		return
	}
	var index AssetIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return
	}
	// 统一走 assetguard：哈希严格 40 位小写 hex、对象名相对路径校验、条数与大小收口。
	// 历史上这里只判 hash != "" 就 obj.Hash[:2]，短哈希会越界 panic，畸形哈希还能让
	// Join 出的落盘路径逃出 objects 目录（远程 DoS / 路径穿越写）。
	safeObjects, rejects, why := auditAssetObjects(index.Objects)
	if why == aoIndexTooMany {
		a.writeLog("资产索引对象条数超过上限 %d，拒绝补全", maxAssetIndexObjects)
		recordSecurityEvent("asset", "high", "reject-asset-index-too-many", "fixMissingAssets",
			fmt.Sprintf("objects=%d limit=%d", len(index.Objects), maxAssetIndexObjects))
		return
	}
	if n := rejects[aoHashBad]; n > 0 {
		recordSecurityEvent("asset", "high", "reject-bad-asset-hash", "fixMissingAssets",
			fmt.Sprintf("count=%d", n))
	}
	objectsDir := filepath.Join(mcDir, "assets", "objects")
	missingCount, downloadedCount := 0, 0
	total := len(safeObjects)
	for i, obj := range safeObjects {
		sub, objPath, ok := planAssetObjectDest(objectsDir, obj.Hash)
		if !ok {
			continue
		}
		if inspectRegularFile(objPath).trustable() {
			continue
		}
		missingCount++
		originalURL := fmt.Sprintf("https://resources.download.minecraft.net/%s/%s", sub, obj.Hash)
		urls := a.getMirrorURLs(originalURL)
		a.emitProgress("downloading", fmt.Sprintf("补全资源 %d/%d", i+1, total), int64(i+1), int64(total))
		// objPath 的父目录由 downloadFromMirrors 内部统一按 0700 创建/收权。
		if a.downloadAssetObject(urls, objPath, obj.Hash) {
			downloadedCount++
		}
	}
	if len(rejects) > 0 {
		rejectedTotal := 0
		for _, n := range rejects {
			rejectedTotal += n
		}
		a.writeLog("资产索引存在 %d 个非法对象，已跳过", rejectedTotal)
	}
	if missingCount > 0 {
		a.writeLog("资源文件补全: 缺失 %d 个, 成功下载 %d 个", missingCount, downloadedCount)
	}
}

// 下载体积上限，防止恶意服务器用无限流把磁盘/内存写爆。
const (
	maxJavaInstallerBytes   = 500 << 20 // 500 MiB，JRE 安装包实际 ~40-70 MiB
	maxAuthlibPrefetchBytes = 1 << 20   // 1 MiB，authlibinjector 抓取的皮肤站首页
	maxVersionManifestBytes = 8 << 20   // 8 MiB，版本清单/资产索引 JSON
)

func extractNatives(jarPath string, destDir string) (int, error) {
	return extractNativesWithLimits(jarPath, destDir, maxNativeEntryBytes, maxNativeTotalBytes)
}
