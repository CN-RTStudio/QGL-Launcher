package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolveWorldDir(savesDir, worldName string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"worldbackup", "世界名校验未通过: "+reason)
		return "", worldError("世界目录名不合法: " + reason)
	}
	worldDir := filepath.Join(savesDir, cleanName)
	// 直接 Lstat（不跟随）：世界根必须是一个真实目录；符号链接根一律拒绝，防止
	// saves 里预置链接把外部目录当成世界打包。注意不能用 isSymlinkOrSpecial——
	// 它把普通目录也归为“非常规”，会误杀所有合法世界。
	li, err := os.Lstat(worldDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", worldError("世界目录不存在")
		}
		return "", worldError("检查世界目录失败")
	}
	if li.Mode()&os.ModeSymlink != 0 {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "世界目录是符号链接，拒绝: "+cleanName)
		return "", worldError("拒绝备份符号链接形式的世界目录")
	}
	if !li.IsDir() {
		return "", worldError("目标不是世界目录")
	}
	if !PathWithinRoot(worldDir, savesDir) {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "世界真实路径越出 saves 根: "+cleanName)
		return "", worldError("世界路径越界")
	}
	return worldDir, nil
}

func planWorldFiles(worldDir string, lim WorldBackupLimits) ([]worldPlannedFile, int64, error) {
	planned := make([]worldPlannedFile, 0, 256)
	var total int64

	walkErr := filepath.WalkDir(worldDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == worldDir {
			return nil
		}
		rel, relErr := filepath.Rel(worldDir, path)
		if relErr != nil || strings.HasPrefix(filepath.ToSlash(rel), "../") || rel == ".." {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界内出现越界相对路径: "+path)
			return worldError("世界内存在越界路径")
		}
		if d.IsDir() {
			// 子目录放行继续遍历；空目录结构无需备份，文件的父目录在解包时重建。
			return nil
		}
		// 走到这里只能是普通文件：符号链接 / 设备 / 管道 / 套接字一律拒绝，
		// 绝不跟随或落地（同样不能用把目录误判为特殊的 isSymlinkOrSpecial）。
		if mode := d.Type(); mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界内存在符号链接或特殊文件，拒绝: "+rel)
			return worldError("世界内存在不允许的链接或特殊文件")
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		size := info.Size()
		if size < 0 {
			return worldError("文件体积非法")
		}
		if size > lim.MaxEntryBytes {
			return worldError(fmt.Sprintf("世界文件 %s 体积 %d 超过单文件上限", rel, size))
		}
		if size > lim.MaxTotalBytes-total {
			return worldError("世界总体积超过备份上限")
		}
		total += size
		if len(planned) >= lim.MaxEntries {
			return worldError("世界文件条目数超过上限")
		}
		planned = append(planned, worldPlannedFile{
			abs:  path,
			rel:  filepath.ToSlash(rel),
			size: size,
		})
		return nil
	})
	if walkErr != nil {
		return nil, 0, walkErr
	}
	if len(planned) == 0 {
		return nil, 0, worldError("世界目录为空，没有可备份的文件")
	}
	return planned, total, nil
}
