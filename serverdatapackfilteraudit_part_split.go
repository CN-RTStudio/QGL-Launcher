package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func pfAuditPack(audit *PackFilterAudit, root, pack, dir string) {
	metaPath := filepath.Join(dir, "pack.mcmeta")
	info, err := os.Lstat(metaPath)
	if err != nil {
		audit.add(root, pack, pfReasonMissing, "缺少 pack.mcmeta", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(root, pack, pfReasonSymlink, "pack.mcmeta 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(root, pack, pfReasonUnreadable, "pack.mcmeta 不是普通文件", true)
		return
	}
	if info.Size() > pfMaxFileBytes {
		audit.add(root, pack, pfReasonTooLarge, fmt.Sprintf("元数据 %d 字节", info.Size()), true)
		return
	}
	if info.Mode().Perm()&0o022 != 0 {
		audit.add(root, pack, pfReasonWorldWritable, fmt.Sprintf("权限 %#o 允许他人写入", info.Mode().Perm()), true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		audit.add(root, pack, pfReasonWorldReadable, fmt.Sprintf("权限 %#o 允许他人读取", info.Mode().Perm()), false)
	}
	raw, readErr := readBoundedFile(metaPath, pfMaxFileBytes)
	if readErr != nil {
		audit.add(root, pack, pfReasonUnreadable, readErr.Error(), false)
		return
	}
	pfAuditMeta(audit, root, pack, raw)
}

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

func AuditServerDataPackFilters(serverDir string) PackFilterAudit {
	audit := PackFilterAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("server", "", pfReasonMissing, "服务器目录不可用", false)
		return audit
	}
	for _, root := range pfPackRoots {
		pfAuditRoot(&audit, root)
	}
	if audit.Packs == 0 {
		audit.add("datapacks", "", pfReasonOK, "未发现数据包", false)
	}
	return audit
}
