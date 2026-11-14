package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func pfAuditRoot(audit *PackFilterAudit, root string) {
	path := filepath.Join(audit.Dir, filepath.FromSlash(root))
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			audit.add(root, "", pfReasonUnreadable, err.Error(), false)
		}
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(root, "", pfReasonSymlink, "数据包目录是符号链接", true)
		return
	}
	if !info.IsDir() {
		audit.add(root, "", pfReasonUnreadable, "数据包路径不是目录", true)
		return
	}
	entries, readErr := os.ReadDir(path)
	if readErr != nil {
		audit.add(root, "", pfReasonUnreadable, readErr.Error(), false)
		return
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		count++
		if count > pfMaxPacks {
			audit.add(root, "", pfReasonEntryCap, "数据包数量超出扫描上限", false)
			break
		}
		audit.Packs++
		pfAuditPack(audit, root, entry.Name(), filepath.Join(path, entry.Name()))
	}
	if count > pfMaxPacks {
		audit.add(root, "", pfReasonTooManyPacks, fmt.Sprintf("数据包 %d 个", count), true)
	}
}
