package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
func saveModAuditSnapshot(path string, snap *ModAuditSnapshot) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writePrivateJSONBounded(path, snap, 16<<20)
}

// ---- 对账 ----

// auditModsAgainstBaseline 把当前 mods 目录与基线账本对账，产出差异报告。
// current 为当前快照；baseline 可为 nil（无基线 -> 全量视为新增）。
func auditModsAgainstBaseline(current *ModAuditSnapshot, baseline *ModAuditSnapshot) ModAuditReport {
	report := ModAuditReport{
		Added:    []ModAuditDelta{},
		Missing:  []ModAuditDelta{},
		Tampered: []ModAuditDelta{},
	}
	if current == nil {
		return report
	}
	byDir := map[string]map[string]ModAuditEntry{}
	baseByDir := map[string]map[string]ModAuditEntry{}
	for _, d := range current.Dirs {
		byDir[d.Dir] = map[string]ModAuditEntry{}
		for _, e := range d.Entries {
			byDir[d.Dir][e.RelPath] = e
		}
		report.Total += len(d.Entries)
	}
	if baseline != nil {
		for _, d := range baseline.Dirs {
			baseByDir[d.Dir] = map[string]ModAuditEntry{}
			for _, e := range d.Entries {
				baseByDir[d.Dir][e.RelPath] = e
			}
		}
	}
	dirNames := []string{}
	seen := map[string]bool{}
	for name := range byDir {
		if !seen[name] {
			seen[name] = true
			dirNames = append(dirNames, name)
		}
	}
	for name := range baseByDir {
		if !seen[name] {
			seen[name] = true
			dirNames = append(dirNames, name)
		}
	}
	sort.Strings(dirNames)

	for _, dirName := range dirNames {
		cur := byDir[dirName]
		base := baseByDir[dirName]
		for rel, e := range cur {
			b, ok := base[rel]
			if !ok {
				report.Added = append(report.Added, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: e.Name, Kind: "added",
					Current: e.Size, Detail: "基线中没有该文件，来源未经验证",
				})
				continue
			}
			if b.Size != e.Size || b.UMFS != e.UMFS {
				report.Tampered = append(report.Tampered, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: e.Name, Kind: "tampered",
					Baseline: b.Size, Current: e.Size,
					Detail: "文件体积或哈希与基线不一致，可能被改写",
				})
				continue
			}
			report.Consistent++
		}
		for rel, b := range base {
			if _, ok := cur[rel]; !ok {
				report.Missing = append(report.Missing, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: b.Name, Kind: "missing",
					Baseline: b.Size, Detail: "基线中存在但当前目录已缺失",
				})
			}
		}
	}
	report.HasRisks = len(report.Added) > 0 || len(report.Missing) > 0 || len(report.Tampered) > 0
	return report
}

// modAuditSummaryText 生成一段给审计事件用的中文摘要。
func modAuditSummaryText(r ModAuditReport) string {
	var parts []string
	if len(r.Tampered) > 0 {
		parts = append(parts, fmt.Sprintf("篡改 %d", len(r.Tampered)))
	}
	if len(r.Added) > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d", len(r.Added)))
	}
	if len(r.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("缺失 %d", len(r.Missing)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("mods 目录完整性一致（%d 个文件）", r.Total)
	}
	return "mods 目录完整性异常: " + strings.Join(parts, "、") +
		fmt.Sprintf("（共 %d 个文件）", r.Total)
}

// modAuditFileDigest 流式计算文件的 UMFS 摘要；超过单文件上界时返回 errLocalFileTooLarge。
func modAuditFileDigest(path string, maxBytes int64) (string, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if maxBytes > 0 && fi.Size() > maxBytes {
		return "", fi.Size(), errLocalFileTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := NewUMFSHash()
	written, err := io.Copy(h, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if maxBytes > 0 && written > maxBytes {
		return "", written, errLocalFileTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), written, nil
}

// collectModAuditDir 为一个 mods 目录生成账本快照。返回条目、跳过数、是否触及上限。
func collectModAuditDir(dir string, lim ModAuditLimits) ([]ModAuditEntry, int, bool, error) {
	relPaths, skipped, limitHit := listModAuditFiles(dir, lim)
	entries := make([]ModAuditEntry, 0, len(relPaths))
	var total int64
	for _, rel := range relPaths {
		if int64(len(entries)) >= int64(lim.MaxEntries) {
			limitHit = true
			skipped++
			break
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		sum, size, err := modAuditFileDigest(full, lim.MaxEntryBytes)
		if err != nil {
			if errors.Is(err, errLocalFileTooLarge) {
				limitHit = true
				skipped++
				continue
			}
			skipped++
			continue
		}
		if lim.MaxTotalBytes > 0 && total+size > lim.MaxTotalBytes {
			limitHit = true
			skipped++
			continue
		}
		total += size
		entry := ModAuditEntry{
			RelPath: rel,
			Name:    filepath.Base(rel),
			Size:    size,
			UMFS:    sum,
		}
		if fi, e2 := os.Stat(full); e2 == nil {
			entry.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}
	return entries, skipped, limitHit, nil
}
