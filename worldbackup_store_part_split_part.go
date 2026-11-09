package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// isWorldDirEmpty 报告目录是否不含任何条目。解压后用它兜底发现“空备份”。
func isWorldDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		return false, err
	}
	return len(names) == 0, nil
}

// allocateRestoreDir 在 saves 下为恢复结果分配一个不存在的目录：
// saves/<world>-restored-<stamp>，冲突时追加 -01..。绝不覆盖既有世界。
func allocateRestoreDir(savesDir, worldName, stamp string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	if !validateWorldStamp(stamp) {
		return "", worldError("时间戳不合法")
	}
	base := cleanName + "-restored-" + stamp
	if len(base) > 200 {
		return "", worldError("恢复目录名过长")
	}
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%02d", base, i)
		}
		target := filepath.Join(savesDir, name)
		if !PathWithinRoot(target, savesDir) {
			return "", worldError("恢复目录解析越界")
		}
		if _, err := os.Lstat(target); err != nil {
			if os.IsNotExist(err) {
				return target, nil
			}
			return "", err
		}
	}
	return "", worldError("无法为恢复结果分配唯一目录")
}
