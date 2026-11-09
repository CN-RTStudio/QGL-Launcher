package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// umfsFileHex 计算文件的 UMFS 摘要（小写 hex），用于本地备份完整性核对。
func umfsFileHex(path string) (string, error) {
	return umfsFile(path)
}

// worldBackupDirFor 返回某世界的备份目录 root/<world>，并保证名段安全。
func worldBackupDirFor(root, worldName string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	dir := filepath.Join(root, cleanName)
	if !PathWithinRoot(dir, root) {
		return "", worldError("备份目录解析越界")
	}
	return dir, nil
}

// uniqueStampZipPath 在备份目录内为时间戳分配一个不存在的 zip 路径，
// 极端的同一秒连续备份用 -01.. 后缀避让，绝不覆盖既有备份。
func uniqueStampZipPath(dir, stamp string) (string, error) {
	if !validateWorldStamp(stamp) {
		return "", worldError("时间戳不合法")
	}
	candidate := filepath.Join(dir, stamp+".zip")
	for i := 0; i < 100; i++ {
		if i == 0 {
			candidate = filepath.Join(dir, stamp+".zip")
		} else {
			candidate = filepath.Join(dir, fmt.Sprintf("%s-%02d.zip", stamp, i))
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", worldError("同一时间戳备份过多，无法分配文件名")
}

// zipPathToManifestPath 返回与某个 zip 配套的清单路径。
func zipPathToManifestPath(zipPath string) string {
	return strings.TrimSuffix(zipPath, ".zip") + ".json"
}
