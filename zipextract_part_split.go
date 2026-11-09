package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
)

func zipResolveParentInside(root, dest string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("解析解压根目录真实路径失败: %v", err)
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("创建解压目录失败: %v", err)
	}
	parentReal, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("解析条目父目录真实路径失败: %v", err)
	}
	if !PathWithinRoot(parentReal, rootReal) {
		return fmt.Errorf("条目父目录真实路径越出解压根目录(junction/symlink 逃逸): %s", parentReal)
	}
	return nil
}

// extractPlannedZipEntries 按预检计划顺序落盘，并在真实复制时再次核对总量
// （元数据可能撒谎）。返回实际写入字节数与文件条目数。
func extractPlannedZipEntries(plan []zipPlannedEntry, destDir string, lim zipExtractLimits, logf func(string, ...any)) (int64, int, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return 0, 0, fmt.Errorf("创建解压根目录失败: %v", err)
	}

	var totalWritten int64
	fileCount := 0
	for _, pe := range plan {
		destPath := filepath.Join(destDir, filepath.FromSlash(pe.rel))
		if !secureDestUnder(destDir, destPath) {
			err := fmt.Errorf("zip 条目解析后越出目标目录(Zip Slip 防护): %s", pe.file.Name)
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		if err := zipResolveParentInside(destDir, destPath); err != nil {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		if pe.dir {
			if err := os.MkdirAll(destPath, 0700); err != nil {
				return totalWritten, fileCount, fmt.Errorf("创建目录 %s 失败: %v", destPath, err)
			}
			continue
		}

		n, err := writeZipEntrySecure(pe.file, destPath, lim.EntryMax)
		if err != nil {
			return totalWritten, fileCount, err
		}
		totalWritten += n
		fileCount++
		if totalWritten > lim.TotalMax {
			err := fmt.Errorf("zip 实际解压总量超过 %d 字节上限(解压炸弹防护)", lim.TotalMax)
			recordSecurityEvent(auditCategoryZip, auditSeverityWarn, auditActionBlocked, "zipextract", err.Error())
			return totalWritten, fileCount, err
		}
		logf("解压条目完成: %s (%d 字节)", pe.rel, n)
	}
	return totalWritten, fileCount, nil
}

// extractZipPrefixes 是调用方最常用的一站式入口：预检 + 落盘。
// prefixes 中靠前的前缀优先匹配。
func extractZipPrefixes(files []*zip.File, destDir string, prefixes []string, lim zipExtractLimits, logf func(string, ...any)) (int64, int, error) {
	plan, declared, err := planZipEntries(files, prefixes, lim)
	if err != nil {
		return 0, 0, err
	}
	if declared > lim.TotalMax {
		return 0, 0, fmt.Errorf("zip 声明总量 %d 超过上限 %d(解压炸弹防护)", declared, lim.TotalMax)
	}
	return extractPlannedZipEntries(plan, destDir, lim, logf)
}
