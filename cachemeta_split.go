package main

import (
	"fmt"
	"strings"
)

func loadCachedFileMeta(destPath string) (cachedFileMeta, bool) {
	var m cachedFileMeta
	// 侧车是本地小 JSON，走有界读取：缺失 / 损坏 / 被改成超大体积都按“无缓存”回退，
	// 绝不无界整体读入；超量由 readLocalJSONBounded 写安全审计。
	if err := readLocalJSONBounded(metaPathFor(destPath), &m, maxCachedFileMetaBytes, "下载缓存侧车元数据"); err != nil {
		return m, false
	}
	return m, true
}
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
