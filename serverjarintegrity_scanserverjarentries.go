package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"
)

func scanServerJarEntries(path string) (int, []string, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return 0, nil, err
	}
	defer reader.Close()
	var suspicious []string
	count := 0
	for _, entry := range reader.File {
		count++
		if count > serverJarMaxEntries {
			suspicious = append(suspicious, fmt.Sprintf("条目数超过 %d", serverJarMaxEntries))
			return count, suspicious, nil
		}
		if suspiciousServerJarEntry(entry.Name) {
			suspicious = append(suspicious, entry.Name)
		}
		if entry.UncompressedSize64 > uint64(serverJarMaxEntryBytes) {
			suspicious = append(suspicious, fmt.Sprintf("%s 展开后超过上限", entry.Name))
		}
	}
	return count, suspicious, nil
}

func AuditServerJar(path string, sidecar func(string) (bool, bool)) (ServerJarAudit, error) {
	audit := ServerJarAudit{Path: path, Reason: serverJarReasonOK}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Reason = serverJarReasonMissing
			return audit, nil
		}
		return audit, fmt.Errorf("检查服务端 JAR 失败: %v", err)
	}
	audit.Present = true
	audit.Size = info.Size()
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Symlink = true
		audit.Reason = serverJarReasonSymlink
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Reason = serverJarReasonSymlink
		return audit, nil
	}
	if info.Size() == 0 {
		audit.Reason = serverJarReasonEmpty
		return audit, nil
	}
	if info.Size() > serverJarMaxScanBytes {
		audit.Reason = serverJarReasonTooLarge
		return audit, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return audit, fmt.Errorf("打开服务端 JAR 失败: %v", err)
	}
	defer file.Close()

	header := make([]byte, serverJarHeaderBytes)
	n, err := io.ReadFull(file, header)
	if err != nil && err != io.ErrUnexpectedEOF {
		return audit, fmt.Errorf("读取服务端 JAR 头部失败: %v", err)
	}
	header = header[:n]

	tailSize := int64(serverJarTailScanBytes)
	if info.Size() < tailSize {
		tailSize = info.Size()
	}
	tail := make([]byte, tailSize)
	if _, err := file.Seek(info.Size()-tailSize, io.SeekStart); err != nil {
		return audit, fmt.Errorf("定位服务端 JAR 尾部失败: %v", err)
	}
	if _, err := io.ReadFull(file, tail); err != nil && err != io.ErrUnexpectedEOF {
		return audit, fmt.Errorf("读取服务端 JAR 尾部失败: %v", err)
	}

	audit.ZipHeader, audit.ZipCentralDir = auditServerJarMagic(header, tail)
	if !audit.ZipHeader {
		audit.Reason = serverJarReasonNotZip
		return audit, nil
	}
	if !audit.ZipCentralDir {
		audit.Reason = serverJarReasonNoCentralDir
		return audit, nil
	}
	entries, suspicious, scanErr := scanServerJarEntries(path)
	if scanErr != nil {
		audit.Reason = serverJarReasonCorruptZip
		return audit, nil
	}
	audit.Entries = entries
	audit.Suspicious = suspicious
	if len(suspicious) > 0 {
		audit.Reason = serverJarReasonSuspiciousEntry
		return audit, nil
	}

	if sidecar != nil {
		ok, present := sidecar(path)
		audit.SidecarPresent = present
		audit.SidecarOK = ok
		if present && !ok {
			audit.Reason = serverJarReasonSidecarMismatch
			return audit, nil
		}
		if !present {
			audit.Warnings = append(audit.Warnings,
				"服务端 JAR 缺少本地侧车摘要，本次仅校验 ZIP 结构；建议重新下载以恢复强校验")
		}
	}

	return audit, nil
}

func describeServerJarAudit(audit ServerJarAudit) string {
	var parts []string
	parts = append(parts, audit.Describe())
	if audit.Size > 0 {
		parts = append(parts, fmt.Sprintf("大小 %d 字节", audit.Size))
	}
	if audit.SidecarPresent {
		parts = append(parts, "侧车已校验")
	}
	if audit.Entries > 0 {
		parts = append(parts, fmt.Sprintf("条目 %d 个", audit.Entries))
	}
	if len(audit.Warnings) > 0 {
		parts = append(parts, strings.Join(audit.Warnings, "；"))
	}
	return strings.Join(parts, "，")
}
