package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func adAuditDir(audit *AdvancementAudit, rel string) {
	path := filepath.Join(audit.Dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.add(rel, "", adReasonUnreadable, err.Error(), false)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(rel, "", adReasonSymlink, "进度目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(rel, "", adReasonUnreadable, "进度路径不是目录", true)
		return
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		audit.add(rel, "", adReasonUnreadable, readErr.Error(), false)
		return
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		count++
		if count > adMaxFiles {
			audit.add(rel, "", adReasonTooManyFiles, fmt.Sprintf("进度文件 %d 个", count), true)
			break
		}
		audit.Files++
		info, infoErr := entry.Info()
		if infoErr != nil {
			audit.add(rel, name, adReasonUnreadable, infoErr.Error(), false)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, name, adReasonSymlink, "进度文件是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(rel, name, adReasonUnreadable, "进度文件不是普通文件", true)
			continue
		}
		if !adFilePattern.MatchString(name) {
			audit.add(rel, name, adReasonBadFileName, "文件名不是标准 UUID", false)
		}
		if info.Size() > adMaxFileBytes {
			audit.add(rel, name, adReasonTooLarge, fmt.Sprintf("进度文件 %d 字节", info.Size()), true)
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(rel, name, adReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
		}
		raw, readErr := readBoundedFile(filepath.Join(path, name), adMaxFileBytes)
		if readErr != nil {
			audit.add(rel, name, adReasonUnreadable, readErr.Error(), false)
			continue
		}
		if depth := adJSONDepth(raw); depth > adMaxDepth {
			audit.add(rel, name, adReasonDeepNesting, fmt.Sprintf("嵌套深度 %d", depth), true)
			continue
		}
		adAuditPayload(audit, rel, name, raw)
	}
}
