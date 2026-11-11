package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func listModAuditFiles(dir string, lim ModAuditLimits) ([]string, int, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, false
	}
	relPaths := []string{}
	skipped := 0
	limitHit := false
	subdirCount := 0
	for _, e := range entries {
		if len(relPaths) >= lim.MaxEntries {
			limitHit = true
			skipped++
			continue
		}
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			// 符号链接指向目录时 e.IsDir() 为 false，已被特殊项跳过；此处是真目录。
			if subdirCount >= modAuditMaxSubdirs {
				limitHit = true
				skipped++
				continue
			}
			subdirCount++
			sub, err := os.ReadDir(full)
			if err != nil {
				skipped++
				continue
			}
			for _, se := range sub {
				if len(relPaths) >= lim.MaxEntries {
					limitHit = true
					skipped++
					continue
				}
				if se.IsDir() {
					continue // 只下一层，更深的子目录不进账本（属扫描范围边界，不计跳过）
				}
				subFull := filepath.Join(full, se.Name())
				if bad, e2 := isSymlinkOrSpecial(subFull); e2 != nil || bad {
					skipped++
					continue
				}
				relPaths = append(relPaths,
					filepath.ToSlash(filepath.Join(e.Name(), se.Name())))
			}
			continue
		}
		if bad, e2 := isSymlinkOrSpecial(full); e2 != nil || bad {
			skipped++
			continue
		}
		relPaths = append(relPaths, filepath.ToSlash(e.Name()))
	}
	sort.Strings(relPaths)
	return relPaths, skipped, limitHit
}

// ---- 基线读写 ----

// buildModAuditSnapshot 为多个 mods 目录生成一张基线账本。dirs 为目录名（非绝对
// 路径），absRoots 与之对齐的绝对根。
func buildModAuditSnapshot(absRoots []string, lim ModAuditLimits) (*ModAuditSnapshot, int, bool, error) {
	snap := &ModAuditSnapshot{
		Version:   modAuditBaselineVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Dirs:      []ModAuditDir{},
	}
	totalSkipped := 0
	anyLimit := false
	for _, abs := range absRoots {
		if abs == "" {
			continue
		}
		entries, skipped, limitHit, err := collectModAuditDir(abs, lim)
		totalSkipped += skipped
		if limitHit {
			anyLimit = true
		}
		if err != nil {
			continue
		}
		if len(entries) == 0 {
			continue
		}
		snap.Dirs = append(snap.Dirs, ModAuditDir{
			Dir:     filepath.Base(abs),
			Entries: entries,
		})
	}
	return snap, totalSkipped, anyLimit, nil
}

// loadModAuditSnapshot 有界读 + 逐字段净化基线账本。文件不存在返回 nil（首次基线）。
func loadModAuditSnapshot(path string) (*ModAuditSnapshot, error) {
	raw := &ModAuditSnapshot{}
	if err := readLocalJSONBounded(path, raw, 16<<20, "mods 审计基线"); err != nil {
		if os.IsNotExist(err) || errors.Is(err, errLocalFileTooLarge) {
			return nil, nil
		}
		return nil, err
	}
	if raw.Version != modAuditBaselineVersion {
		return nil, fmt.Errorf("mods 审计基线版本不兼容")
	}
	out := &ModAuditSnapshot{Version: raw.Version, CreatedAt: raw.CreatedAt, Dirs: []ModAuditDir{}}
	for _, d := range raw.Dirs {
		if !modAuditSafeRelPath(d.Dir) {
			continue
		}
		clean := ModAuditDir{Dir: d.Dir, Entries: []ModAuditEntry{}}
		for _, e := range d.Entries {
			cp := e
			if sanitizeModAuditEntry(&cp) {
				clean.Entries = append(clean.Entries, cp)
			}
		}
		if len(clean.Entries) > 0 {
			out.Dirs = append(out.Dirs, clean)
		}
	}
	return out, nil
}

// saveModAuditSnapshot 原子私有写基线账本（0600）。
