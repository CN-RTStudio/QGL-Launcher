package main

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

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
