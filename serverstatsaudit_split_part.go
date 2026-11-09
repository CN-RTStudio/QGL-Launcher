package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func stAuditDir(audit *StatsAudit, rel string) {
	path := filepath.Join(audit.Dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.add(rel, "", stReasonUnreadable, err.Error(), false)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, "", stReasonSymlink, "统计目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(rel, "", stReasonUnreadable, "统计路径不是目录", true)
		return
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		audit.add(rel, "", stReasonUnreadable, readErr.Error(), false)
		return
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		count++
		if count > stMaxFiles {
			audit.add(rel, "", stReasonEntryCap, "统计文件数量超出扫描上限", false)
			break
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			audit.add(rel, name, stReasonUnreadable, infoErr.Error(), false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, name, stReasonSymlink, "统计文件是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(rel, name, stReasonUnreadable, "统计文件不是普通文件", true)
			continue
		}
		stAuditFile(audit, rel, name, filepath.Join(path, name), info)
	}
	if count > stMaxFiles {
		audit.add(rel, "", stReasonTooManyFiles, fmt.Sprintf("统计文件 %d 个", count), true)
	}
}

func AuditServerStats(serverDir string) StatsAudit {
	audit := StatsAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", stReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, rel := range stStatDirs {
		stAuditDir(&audit, rel)
	}
	if audit.Bytes > stMaxTotalBytes {
		audit.add("world/stats", "", stReasonTotalBytes, fmt.Sprintf("统计总量 %d 字节", audit.Bytes), false)
	}
	if audit.Files == 0 {
		audit.add("world/stats", "", stReasonOK, "未发现玩家统计文件", false)
	}
	return audit
}
