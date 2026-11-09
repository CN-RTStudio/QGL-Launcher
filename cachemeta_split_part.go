package main

import (
	"os"
	"strings"
)

func (a *App) verifyCachedFile(destPath, officialSHA1 string) bool {
	state := inspectRegularFile(destPath)
	if !state.trustable() || state.Size <= 0 {
		return false
	}
	official := strings.ToLower(strings.TrimSpace(officialSHA1))

	meta, hasMeta := loadCachedFileMeta(destPath)
	if !hasMeta {
		// 老缓存 / 全新环境：直接回退到官方 SHA1，通过后顺带把新元数据补齐。
		if a.checkFileHash(destPath, official) {
			_ = a.saveCachedFileMeta(destPath, official)
			return true
		}
		return false
	}

	// 侧车记录的权威 SHA1 与本次期望不一致，说明侧车不属于当前对象。
	if official != "" && meta.SHA1 != "" && !strings.EqualFold(meta.SHA1, official) {
		return false
	}
	if meta.Size > 0 && state.Size != meta.Size {
		return false
	}

	switch {
	case meta.UMFS != "":
		got, err := umfsFile(destPath)
		if err != nil {
			return false
		}
		return got == meta.UMFS // 字段在却对不上 => 损坏/被改，直接失效，不向更弱算法降级
	case meta.SHA512 != "":
		got, err := sha512File(destPath)
		if err != nil {
			return false
		}
		if got != meta.SHA512 {
			return false
		}
		// SHA512 命中但侧车还没有 UMFS：升级补写一次。
		if official != "" {
			_ = a.saveCachedFileMeta(destPath, official)
		}
		return true
	default:
		// 侧车只有权威 SHA1：用官方 SHA1 兜底，通过后升级补 UMFS/SHA512。
		if a.checkFileHash(destPath, official) {
			_ = a.saveCachedFileMeta(destPath, official)
			return true
		}
		return false
	}
}

// removeCachedFileMeta 在删除/替换缓存文件时一并清理侧车，避免陈旧元数据残留。
func removeCachedFileMeta(destPath string) {
	_ = os.Remove(metaPathFor(destPath))
}
