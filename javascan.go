package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func searchDriveForJava(drivePath string, results *[]JavaEntry, seen map[string]bool) {
	entries, err := os.ReadDir(drivePath)
	if err != nil {
		return
	}
	// 需要进入搜索的根目录关键字（参考PCL的JavaSearchFolder关键字列表）
	rootKeywords := []string{
		"java", "jdk", "jre", "program", "software", "soft", "app",
		"develop", "dev", "tools", "runtime", "env", "游戏", "game",
		"mc", "minecraft", "launch", "启动", "运行", "应用",
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		// 直接检查该目录下是否有 bin/javaw.exe
		javawPath := filepath.Join(drivePath, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}
		// 判断是否需要进入该目录搜索
		shouldEnter := false
		for _, kw := range rootKeywords {
			if strings.Contains(lowerName, kw) {
				shouldEnter = true
				break
			}
		}
		if shouldEnter {
			// 不跟随 junction / 符号链接，避免扫到其它卷或陷入联接环。
			if isReparsePointDir(entry) {
				continue
			}
			searchDirForJava(filepath.Join(drivePath, name), results, seen, 4)
		}
	}
}

const maxJavaVersionOutput int64 = 1 << 20 // 1 MiB
type limitedWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
	max int64
	n   int64
}
