package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func copyDirContents(srcDir string, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// ReadDir 不跟随链接：任何非常规文件（符号链接 / 设备 / 管道等）一律跳过。
		if entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > maxCopyDirEntryBytes || total+size > maxNativeTotalBytes {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		// copyFileSecure 内部会再做一次源链接检查、目标链接拒绝，并以 LimitReader
		// 多读 1 字节发现“声明大小正常但读取中持续增长”的文件。
		if err := copyFileSecure(srcPath, dstPath, 0600, maxCopyDirEntryBytes); err != nil {
			continue
		}
		total += size
	}
	return nil
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
