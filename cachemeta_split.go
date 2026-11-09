package main

import (
	"fmt"
	"os"
	"strings"
)

// loadCachedFileMeta 读取并解析侧车元数据；不存在或损坏时返回 ok=false。
func loadCachedFileMeta(destPath string) (cachedFileMeta, bool) {
	var m cachedFileMeta
	// 侧车是本地小 JSON，走有界读取：缺失 / 损坏 / 被改成超大体积都按“无缓存”回退，
	// 绝不无界整体读入；超量由 readLocalJSONBounded 写安全审计。
	if err := readLocalJSONBounded(metaPathFor(destPath), &m, maxCachedFileMetaBytes, "下载缓存侧车元数据"); err != nil {
		return m, false
	}
	return m, true
}

// saveCachedFileMeta 在文件已通过官方 SHA1 校验后，计算并原子写入本地摘要。
// UMFS / SHA512 的计算失败不致命：缺哪项就只写哪项，校验时按回退链处理。
func (a *App) saveCachedFileMeta(destPath, officialSHA1 string) error {
	state := inspectRegularFile(destPath)
	if !state.trustable() {
		return fmt.Errorf("缓存对象不是可信任的普通文件: %s", describeUntrustedFile(state, destPath))
	}
	m := cachedFileMeta{
		SHA1: strings.ToLower(strings.TrimSpace(officialSHA1)),
		Size: state.Size,
	}
	if sum, err := umfsFile(destPath); err == nil && sum != "" {
		m.UMFS = sum
	}
	if sum, err := sha512File(destPath); err == nil && sum != "" {
		m.SHA512 = sum
	}
	// 统一走有界原子私有写内核（0700 + fsync + rename + 拒符号链接 + 父目录收权），
	// 替换本函数此前手写的 CreateTemp/Write/Chmod/Close/Rename——旧实现缺 fsync 与
	// 符号链接防护，崩溃或预置链接时可能留下半截 / 写穿的侧车。
	return writePrivateJSON(metaPathFor(destPath), m)
}

// verifyCachedFile 判断已缓存文件能否直接复用，摘要顺序 UMFS -> SHA512 -> SHA1。
// officialSHA1 是当前官方清单给出的权威值，用于把侧车绑定到正确对象，
// 防止别的文件留下的同名 .qglmeta 被误用。
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
