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
