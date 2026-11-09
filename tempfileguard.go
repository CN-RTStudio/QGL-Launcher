package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const staleTempMaxAge = time.Hour

type TempFileCleanup struct {
	Path      string
	Removed   bool
	Present   bool
	AgeMillis int64
	Reason    string
}

func prepareTempPath(path string, now time.Time, maxAge time.Duration) (TempFileCleanup, error) {
	out := TempFileCleanup{Path: path, Reason: "absent"}
	if maxAge <= 0 {
		maxAge = staleTempMaxAge
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, fmt.Errorf("检查临时文件失败: %v", err)
	}
	out.Present = true
	out.AgeMillis = now.Sub(info.ModTime()).Milliseconds()
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		out.Reason = "not-regular"
		return out, fmt.Errorf("临时路径 %s 不是普通文件，拒绝删除或复用", path)
	}
	if now.Sub(info.ModTime()) <= maxAge {
		out.Reason = "fresh"
		return out, nil
	}
	if err := os.Remove(path); err != nil {
		return out, fmt.Errorf("清理过期临时文件失败: %v", err)
	}
	out.Removed = true
	out.Reason = "removed"
	return out, nil
}

func staleTempPathFor(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".tmp")
}
