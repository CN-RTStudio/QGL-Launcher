package main

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// worldrestore.go —— 世界 zip“只读预检 / 外部导入 / 恢复后验证”安全内核。
//
// worldbackup.go 负责把世界目录安全地打成 zip（条目路径已校验、权限 0600、
// 原子写、UMFS 摘要），并已实现带 UMFS 完整性核对的 restoreWorldBackup（分配
// 不覆盖的新目录）。本文件补齐同一信任边界上剩余的三个缺口：
//
//  1. inspectWorldZip：恢复 / 导入前的只读预检——条目路径（Zip Slip）、
//     符号链接 / 设备条目、zip bomb（数量与总量上限）、关键文件存在性。
//     不改动任何文件，可先于解压给用户一个“这份 zip 能不能用”的答案。
//  2. importExternalWorldZip：把用户外部拿到的世界 zip 导入为一个全新世界
//     （要求 level.dat、目标同名时显式允许覆盖或拒绝）。
//  3. verifyWorldRestore：恢复 / 导入完成后的完整性复核（level.dat 存在、
//     目标目录未越界），并给出目标目录的 UMFS 聚合指纹。
//
// 解压落地复用 zipextract.go 的 extractZipPrefixes（无前缀 = 接受全部条目），
// 路径 / 特殊类型 / 数量与总量上限的防护不在这里重写第二套。

// RestoreLimits 是恢复 / 导入过程的总量与条数上限（防 zip bomb 与 inode 耗尽）。
type RestoreLimits struct {
	EntryMax   int64
	TotalMax   int64
	MaxEntries int
}

func defaultRestoreLimits() RestoreLimits {
	return RestoreLimits{
		EntryMax:   worldMaxEntryCeiling,
		TotalMax:   worldMaxTotalCeiling,
		MaxEntries: 40000,
	}
}

func normalizeRestoreLimits(l RestoreLimits) RestoreLimits {
	if l.EntryMax <= 0 || l.EntryMax > worldMaxEntryCeiling {
		l.EntryMax = worldMaxEntryCeiling
	}
	if l.TotalMax <= 0 || l.TotalMax > worldMaxTotalCeiling {
		l.TotalMax = worldMaxTotalCeiling
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 40000
	}
	if l.EntryMax > l.TotalMax {
		l.EntryMax = l.TotalMax
	}
	return l
}

// WorldRestoreMeta 是一次恢复 / 导入后的报告。
type WorldRestoreMeta struct {
	WorldName  string `json:"worldName"`
	Action     string `json:"action"` // restore | import
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	DestDir    string `json:"destDir"`
	UMFS       string `json:"umfs"`
	FinishedAt string `json:"finishedAt"`
}

// worldRestoreOptions 控制恢复 / 导入行为。
type worldRestoreOptions struct {
	AllowOverwrite bool
	Limits         RestoreLimits
}

// zipEntryInfo 是 inspectWorldZip 对单个条目的只读摘要。
type zipEntryInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Dir  bool   `json:"dir"`
}

// ZipInspection 是恢复 / 导入前的只读预检结果。
type ZipInspection struct {
	ZipPath    string         `json:"zipPath"`
	Entries    []zipEntryInfo `json:"entries"`
	EntryCount int            `json:"entryCount"`
	TotalBytes int64          `json:"totalBytes"`
	HasLevel   bool           `json:"hasLevel"`
	HasRegion  bool           `json:"hasRegion"`
	Safe       bool           `json:"safe"`
	Reason     string         `json:"reason,omitempty"`
}

// worldKeyFiles 是判断一个世界 zip / 目录“像不像 Minecraft 世界”的关键文件。
// level.dat 一定存在；region 目录在多数世界存在（老版本 / 空世界可能没有，只做提示）。
var worldKeyFiles = []string{"level.dat", "region/", "session.lock"}

// inspectWorldZip 只读打开 zip 做预检：条目路径安全（复用 secureZipRelPath）、
// 特殊类型拒绝、数量 / 总量上限、关键文件存在性。不落盘、不修改任何文件。
func inspectWorldZip(zipPath string, lim RestoreLimits) (*ZipInspection, error) {
	lim = normalizeRestoreLimits(lim)
	st, err := os.Stat(zipPath)
	if err != nil {
		return nil, fmt.Errorf("读取备份文件失败: %w", err)
	}
	if st.Size() > lim.TotalMax+1<<20 {
		return nil, worldError("备份 zip 本身超过恢复总量上限")
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("打开备份 zip 失败: %w", err)
	}
	defer zr.Close()

	ins := &ZipInspection{ZipPath: zipPath}
	var total int64
	for _, f := range zr.File {
		if ins.EntryCount >= lim.MaxEntries {
			return nil, worldError("备份条目数量超过上限")
		}
		if f.Mode()&unsafeEntryMode != 0 {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
				"worldrestore", fmt.Sprintf("备份 zip 含特殊类型条目(符号链接/设备): %s", f.Name))
			ins.Safe = false
			ins.Reason = "special-entry"
			return ins, nil
		}
		if _, ok := secureZipRelPath(f.Name); !ok {
			recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
				"worldrestore", fmt.Sprintf("备份 zip 含不安全路径条目: %s", f.Name))
			ins.Safe = false
			ins.Reason = "unsafe-path"
			return ins, nil
		}
		ins.Entries = append(ins.Entries, zipEntryInfo{Name: f.Name, Size: int64(f.UncompressedSize64), Dir: f.FileInfo().IsDir()})
		ins.EntryCount++
		total += int64(f.UncompressedSize64)
		if total > lim.TotalMax {
			return nil, worldError("备份展开总量超过上限(zip bomb 防护)")
		}
		if f.Name == "level.dat" {
			ins.HasLevel = true
		}
		if strings.HasPrefix(f.Name, "region/") {
			ins.HasRegion = true
		}
	}
	ins.TotalBytes = total
	ins.Safe = true
	if !ins.HasLevel {
		ins.Reason = "missing-level-dat"
	}
	return ins, nil
}

// resolveRestoreDest 解析恢复目标目录：目标世界名经 validateWorldName 审计，
// 落点必须位于 savesDir 之内（PathWithinRoot 复核）。
func resolveRestoreDest(savesDir, worldName string) (string, error) {
	clean, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界名不合法: " + reason)
	}
	dest := filepath.Join(savesDir, clean)
	if !PathWithinRoot(dest, savesDir) {
		return "", worldError("恢复目标越界")
	}
	return dest, nil
}

// importExternalWorldZip 把用户外部拿到的世界 zip 导入为 savesDir/<targetName>。
// 导入前做只读预检（zip slip / 特殊类型 / bomb），要求 zip 是完整世界（level.dat）。
func importExternalWorldZip(zipPath, savesDir, targetName string, opts worldRestoreOptions) (*WorldRestoreMeta, error) {
	opts.Limits = normalizeRestoreLimits(opts.Limits)
	dest, err := resolveRestoreDest(savesDir, targetName)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dest); err == nil && !opts.AllowOverwrite {
		return nil, worldError("目标世界已存在，未允许覆盖")
	}

	ins, err := inspectWorldZip(zipPath, opts.Limits)
	if err != nil {
		return nil, err
	}
	if !ins.Safe {
		return nil, worldError("导入 zip 预检未通过: " + ins.Reason)
	}
	if !ins.HasLevel {
		return nil, worldError("导入 zip 不是完整的世界备份（缺少 level.dat）")
	}

	if err := ensurePrivateDir(savesDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, fmt.Errorf("创建导入目标失败: %w", err)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("打开导入 zip 失败: %w", err)
	}
	defer zr.Close()

	zlim := zipExtractLimits{
		EntryMax:   opts.Limits.EntryMax,
		TotalMax:   opts.Limits.TotalMax,
		MaxEntries: opts.Limits.MaxEntries,
	}
	total, n, err := extractZipPrefixes(zr.File, dest, []string{""}, zlim, nil)
	if err != nil {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldrestore", fmt.Sprintf("世界导入失败: %v", err))
		return nil, err
	}

	umfsHex, err := umfsDirHex(dest)
	if err != nil {
		umfsHex = ""
	}
	return &WorldRestoreMeta{
		WorldName:  targetName,
		Action:     "import",
		Entries:    n,
		TotalBytes: total,
		DestDir:    dest,
		UMFS:       umfsHex,
		FinishedAt: time.Now().Format("2006-01-02 15:04:05"),
	}, nil
}

// verifyWorldRestore 恢复 / 导入完成后做完整性检查：level.dat 必须存在，
// 目标目录仍是普通目录、未越界。返回检查说明。
func verifyWorldRestore(destDir, worldName string) (bool, string) {
	dest, err := resolveRestoreDest(filepath.Dir(destDir), worldName)
	if err != nil {
		return false, err.Error()
	}
	if filepath.Clean(dest) != filepath.Clean(destDir) {
		return false, "目标目录与预期不一致"
	}
	st, err := os.Stat(filepath.Join(dest, "level.dat"))
	if err != nil || st.IsDir() {
		return false, "level.dat 缺失或异常"
	}
	return true, "世界结构完整（level.dat 存在）"
}

// umfsDirHex 计算目录下所有文件的 UMFS 摘要（按相对路径字典序聚合），
// 作为恢复 / 导入结果的本地完整性指纹。
func umfsDirHex(root string) (string, error) {
	var rels []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	// 字典序保证指纹稳定，与恢复顺序无关。
	sortStrings(rels)
	h := NewUMFSHash()
	for _, rel := range rels {
		hex, err := umfsFileHex(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		h.Write([]byte(rel))
		h.Write([]byte{':'})
		h.Write([]byte(hex))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
