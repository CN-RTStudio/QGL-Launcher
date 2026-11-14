package main

import (
	"os"
	"path/filepath"
)

func sytScan(root, dir string, depth int, a *WorldSymlinkAudit) {
	if depth > sytMaxDepth {
		a.add(dir, sytTooDeep, "目录层级超过上限", true)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(dir, sytUnreadable, err.Error(), true)
		return
	}
	for _, entry := range entries {
		if a.Entries >= sytMaxEntries {
			a.add(dir, sytTooMany, "存档条目数量超过扫描上限", true)
			return
		}
		a.Entries++
		path := filepath.Join(dir, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil {
			a.add(path, sytUnreadable, statErr.Error(), true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				a.add(path, sytLink, "无法解析链接目标", true)
				continue
			}
			if !sytWithinRoot(root, resolved) {
				a.add(path, sytEscape, "链接指向存档根目录之外", true)
				continue
			}
			a.add(path, sytLink, "存档内存在符号链接", false)
			continue
		}
		if info.IsDir() {
			sytScan(root, path, depth+1, a)
			continue
		}
		if !info.Mode().IsRegular() {
			a.add(path, sytSpecial, "存档内存在设备、管道或套接字文件", true)
		}
		continue
	}
}
