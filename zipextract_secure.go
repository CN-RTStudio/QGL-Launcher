package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// secureZipRelPath 校验 zip 条目名（去掉业务前缀后的相对路径）是否安全。
//
// zip 规范规定条目名一律用 '/' 分隔；这里故意不做任何平台相关的 Clean，
// 而是逐段手工过一遍，保证 Windows / Linux 行为一致：
//   - 空名、NUL 字节、反斜杠、前导 '/'、Windows 盘符 / UNC 一律拒绝；
//   - 出现 ".." 段（任何位置）一律拒绝，"."、空段会被折叠；
//   - 折叠后为空（例如 "./" 本身）也拒绝。
func secureZipRelPath(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", false
	}
	if strings.ContainsRune(name, '\\') {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	// Windows 盘符（C:x / C:/x）与传统 DOS 设备名前缀。
	if len(name) >= 2 && name[1] == ':' {
		return "", false
	}

	var segs []string
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", false
		default:
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return "", false
	}
	for _, seg := range segs {
		if zipSegmentUnsafeReason(seg) != "" {
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}

// secureDestUnder 复核目标绝对路径必须位于 root 之内（或等于 root）。
// rel 已在 secureZipRelPath 里验过，这里是落盘前的第二道保险，
// 防止平台路径语义差异或上层拼接失误造成逃逸。归属判定统一走
// pathguard.go 的 PathWithinRoot（Clean + 卷名归一 + 边界前缀比较），
// 不再在这里各写一份 Abs/HasPrefix。
