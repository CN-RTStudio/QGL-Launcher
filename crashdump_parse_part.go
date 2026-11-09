package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// pickLatestDumpEntry 在目录内按文件名前缀/后缀选择本局（modTime >= notBefore）
// 最新的一个非目录、非符号链接条目。返回其完整路径、基名与 mtime。
func pickLatestDumpEntry(dir, prefix, suffix string, notBefore time.Time) (path, name string, mod time.Time, ok bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", time.Time{}, false
	}
	var bestTime time.Time
	for _, entry := range entries {
		// 跳过目录与符号链接（DirEntry.Type 对 symlink 给 ModeSymlink）。
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		fname := entry.Name()
		if !strings.HasPrefix(fname, prefix) || !strings.HasSuffix(fname, suffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.IsDir() {
			continue
		}
		mt := info.ModTime()
		if mt.Before(notBefore) {
			continue
		}
		full := filepath.Join(dir, fname)
		// 二次确认解析结果仍在崩溃目录内，杜绝任何名字携带分隔符的逃逸尝试。
		if resolved, good := PathWithin(dir, full); !good {
			continue
		} else {
			full = resolved
		}
		if !ok || mt.After(bestTime) {
			bestTime = mt
			path, name, mod, ok = full, fname, mt, true
		}
	}
	return path, name, mod, ok
}

// readDumpBounded 通过统一的有界读取载入崩溃产物，超限审计并放弃。
func readDumpBounded(path string) ([]byte, bool) {
	data, err := readBoundedFile(path, crashDumpMaxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			recordSecurityEvent("game-log", auditSeverityWarn, auditActionStripped,
				"crash-dump", "崩溃产物体积超过上限已放弃解析(防内存/磁盘膨胀): "+safeCrashName(path))
			return nil, false
		}
		return nil, false
	}
	return data, true
}

// resolveCrashReportsDir 返回可信的 crash-reports 目录。它必须不是符号链接、
// 且解析后仍位于 gameDir 内——否则若该子目录被预置成指向游戏目录外的链接，
// 直接对其 os.ReadDir 会枚举到外部目录，后续 PathWithin(dir, file) 还会以
// 这个“外部真实目录”为根而误判为合法。
func resolveCrashReportsDir(gameDir string) (string, bool) {
	dir := filepath.Join(gameDir, "crash-reports")
	if IsSymlink(dir) {
		return "", false
	}
	if _, ok := PathWithin(gameDir, dir); !ok {
		return "", false
	}
	return dir, true
}
