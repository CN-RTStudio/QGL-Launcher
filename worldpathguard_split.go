package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func AuditWorldPath(serverDir, levelName string) (WorldPathAudit, error) {
	audit := WorldPathAudit{LevelName: levelName, Reason: worldReasonOK}
	if !safeWorldLevelName(levelName) {
		audit.Reason = worldReasonUnsafeName
		return audit, nil
	}
	root, err := canonicalAbs(serverDir)
	if err != nil {
		return audit, fmt.Errorf("解析服务器目录失败: %v", err)
	}
	target := filepath.Join(root, levelName)
	audit.Path = target
	if !PathWithinRoot(target, root) {
		audit.Reason = worldReasonEscape
		return audit, nil
	}
	info, err := os.Lstat(target)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Warnings = append(audit.Warnings, "世界目录尚不存在，首次启动后由服务端创建")
			return audit, nil
		}
		return audit, fmt.Errorf("检查世界目录失败: %v", err)
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Symlink = true
		audit.Reason = worldReasonSymlink
		return audit, nil
	}
	if !info.IsDir() {
		audit.Reason = worldReasonNotDirectory
		return audit, nil
	}
	return audit, nil
}
