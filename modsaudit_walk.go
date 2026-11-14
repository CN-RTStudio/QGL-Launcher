package main

import (
	"os"
	"path/filepath"
	"sort"
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
