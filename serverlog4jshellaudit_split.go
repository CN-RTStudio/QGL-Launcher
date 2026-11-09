package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func ljScanJarDir(root, rel string, a *Log4jShellAudit) {
	dir := filepath.Join(root, rel)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			relPath = path
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			a.add(relPath, ljReasonSymlink, "日志组件路径为符号链接", true)
			return nil
		}
		if len(filepath.Base(path)) > ljMaxJarName {
			a.add(relPath, ljReasonBadName, "文件名超长", false)
			return nil
		}
		base, version := ljStripJarName(path)
		if base == "" {
			return nil
		}
		a.Jars++
		major, minor, patch, ok := ljParseVersion(version)
		if !ok {
			a.add(relPath, ljReasonBadName, "版本号无法解析: "+version, false)
			return nil
		}
		if ljVersionVulnerable(major, minor) {
			a.add(relPath, ljReasonVulnerable, fmt.Sprintf("log4j-core %d.%d.%d 低于 %s", major, minor, patch, ljVulnVersion), true)
		}
		return nil
	})
}
