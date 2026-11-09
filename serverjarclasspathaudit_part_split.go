package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
)

func jarCPInspect(audit *JarClassPathAudit, path, display string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(display, "", jarCpReasonUnreadable, "jar 不可访问", false)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(display, "", jarCpReasonUnreadable, "jar 是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(display, "", jarCpReasonUnreadable, "jar 不是普通文件", true)
		return
	}
	if info.Size() > jarCpMaxManifestBytes<<12 {
		audit.add(display, "", jarCpReasonTooLarge, "jar 体积异常", true)
		return
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		audit.add(display, "", jarCpReasonNotZip, "无法解析为 zip/jar", true)
		return
	}
	defer reader.Close()
	var manifest *zip.File
	for _, f := range reader.File {
		if strings.EqualFold(f.Name, jarCpManifestPath) {
			manifest = f
			break
		}
	}
	if manifest == nil {
		audit.add(display, "", jarCpReasonNoManifest, "jar 缺少清单文件", false)
		return
	}
	if manifest.UncompressedSize64 > jarCpMaxManifestBytes {
		audit.add(display, "", jarCpReasonTooLarge, "清单文件超过上限", true)
		return
	}
	rc, err := manifest.Open()
	if err != nil {
		audit.add(display, "", jarCpReasonUnreadable, "清单文件不可读", true)
		return
	}
	defer rc.Close()
	buf := make([]byte, jarCpMaxManifestBytes)
	n, err := rc.Read(buf)
	if err != nil && n == 0 {
		audit.add(display, "", jarCpReasonUnreadable, "清单文件读取失败", true)
		return
	}
	if !jarCPScanManifest(audit, display, buf[:n]) {
		return
	}
}

func AuditServerJarClassPath(serverDir string) JarClassPathAudit {
	audit := JarClassPathAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", "", jarCpReasonMissing, "服务器目录不存在", true)
		return audit
	}
	scanned := 0
	for _, root := range jarCpScanRoots {
		dir := filepath.Join(serverDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if scanned >= jarCpMaxJars {
				audit.add(root, "", jarCpReasonTooMany, "jar 数量超过扫描上限", true)
				break
			}
			lower := strings.ToLower(entry.Name())
			if entry.IsDir() || !strings.HasSuffix(lower, ".jar") {
				continue
			}
			display := entry.Name()
			if root != "." {
				display = filepath.Join(root, entry.Name())
			}
			scanned++
			audit.Jars++
			jarCPInspect(&audit, filepath.Join(dir, entry.Name()), display)
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", "", jarCpReasonOK, "Class-Path 均为相对且无远程引用", false)
	}
	return audit
}
