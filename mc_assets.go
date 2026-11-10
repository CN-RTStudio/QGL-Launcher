package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func extractNativesWithLimits(jarPath string, destDir string, entryMax, totalMax int64) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()
	count := 0
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		// 符号链接 / 设备等特殊条目绝不落地，即便伪装成 .dll 后缀。
		if f.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") && !strings.HasSuffix(lowerName, ".jnilib") && !strings.HasSuffix(lowerName, ".so") {
			continue
		}
		// zip 头里声明的解压体积可先廉价挡一刀；真正的边界仍靠 LimitReader，不信任该值。
		if f.UncompressedSize64 > uint64(entryMax) {
			return count, fmt.Errorf("native 条目 %s 声明体积超过单文件上限", f.Name)
		}
		if total >= totalMax || total+int64(f.UncompressedSize64) > totalMax {
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		if state := inspectRegularFile(destPath); state.trustable() && state.Size == f.FileInfo().Size() {
			count++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		limit := entryMax
		if remain := totalMax - total; remain < limit {
			limit = remain
		}
		n, streamErr := secureStreamToFile(rc, destPath, privateFilePerm, limit)
		rc.Close()
		if streamErr != nil {
			if n > limit {
				if limit < entryMax {
					return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
				}
				return count, fmt.Errorf("native 条目 %s 解压后超过单文件上限", fileName)
			}
			continue
		}
		total += n
		count++
	}
	return count, nil
}

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 解压根目录统一收权到 0700（历史上若存在 0755 的 natives 目录会被原样沿用）。
	_ = ensurePrivateDir(nativesDir)
	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}
		// 与下载阶段使用同一套“按真实架构选 Windows natives 键 + ${arch} 替换”
		// 的规则，避免下载和解压挑到不同分类器（旧实现这里只看 windows-64/windows）。
		winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
		nativeKey, hasNative := resolveWindowsNativeKey(lib.Natives, winEnv)
		if !hasNative {
			continue
		}
		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		// 与下载阶段一致，这里必须再次校验 classifier.Path：版本 JSON 来自镜像
		// 站（不可信），而本函数也会被非 DownloadVersion 的其它启动流程调用。
		safeClassifierPath := isSafeRelPath(classifier.Path)
		if safeClassifierPath == "" {
			a.writeLog("跳过不安全的 native jar 路径: %s", classifier.Path)
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", safeClassifierPath)
		if !inspectRegularFile(nativeJarPath).trustable() {
			a.writeLog("native jar 不存在(跳过): %s", nativeJarPath)
			continue
		}
		extracted, err := extractNatives(nativeJarPath, nativesDir)
		if err != nil {
			a.writeLog("解压 native 失败: %s, %v", classifier.Path, err)
		} else if extracted > 0 {
			a.writeLog("解压 native: %s -> %d 个文件", classifier.Path, extracted)
		}
	}
}

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

const maxCopyDirEntryBytes int64 = 256 << 20

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
