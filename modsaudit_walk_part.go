package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

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
func saveModAuditSnapshot(path string, snap *ModAuditSnapshot) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writePrivateJSONBounded(path, snap, 16<<20)
}

// ---- 对账 ----
