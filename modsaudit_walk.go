package main

import (
	"encoding/hex"
	"errors"
	"io"
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
