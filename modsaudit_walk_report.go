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
