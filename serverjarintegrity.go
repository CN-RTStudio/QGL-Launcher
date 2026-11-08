package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	serverJarReasonOK              = "ok"
	serverJarReasonMissing         = "missing"
	serverJarReasonSymlink         = "symlink"
	serverJarReasonEmpty           = "empty"
	serverJarReasonTooLarge        = "too-large"
	serverJarReasonNotZip          = "not-zip"
	serverJarReasonNoCentralDir    = "no-central-directory"
	serverJarReasonSidecarMismatch = "sidecar-mismatch"
	serverJarReasonCorruptZip      = "corrupt-zip"
	serverJarReasonSuspiciousEntry = "suspicious-entry"
	serverJarMaxEntries            = 20000
	serverJarMaxEntryBytes         = int64(256) << 20
	serverJarTailScanBytes         = 64 << 10
	serverJarHeaderBytes           = 4
	serverJarMaxScanBytes          = 512 << 20
)

type ServerJarAudit struct {
	Path           string
	Present        bool
	Symlink        bool
	Size           int64
	ZipHeader      bool
	ZipCentralDir  bool
	SidecarPresent bool
	SidecarOK      bool
	Entries        int
	Suspicious     []string
	Warnings       []string
	Reason         string
}

func (audit ServerJarAudit) Blocking() bool {
	switch audit.Reason {
	case serverJarReasonMissing, serverJarReasonSymlink, serverJarReasonEmpty,
		serverJarReasonTooLarge, serverJarReasonNotZip, serverJarReasonNoCentralDir,
		serverJarReasonSidecarMismatch, serverJarReasonCorruptZip,
		serverJarReasonSuspiciousEntry:
		return true
	default:
		return false
	}
}

func (audit ServerJarAudit) Describe() string {
	switch audit.Reason {
	case serverJarReasonOK:
		return "服务端 JAR 完整性校验通过"
	case serverJarReasonMissing:
		return "服务端 JAR 不存在"
	case serverJarReasonSymlink:
		return "服务端 JAR 是符号链接，拒绝按链接目标执行"
	case serverJarReasonEmpty:
		return "服务端 JAR 为空文件"
	case serverJarReasonTooLarge:
		return fmt.Sprintf("服务端 JAR 超过 %d 字节上限", int64(serverJarMaxScanBytes))
	case serverJarReasonNotZip:
		return "服务端 JAR 不是 ZIP 容器（缺少 PK 头）"
	case serverJarReasonNoCentralDir:
		return "服务端 JAR 缺少 ZIP 中央目录结束记录"
	case serverJarReasonSidecarMismatch:
		return "服务端 JAR 与本地侧车摘要不一致，文件可能被替换"
	case serverJarReasonCorruptZip:
		return "服务端 JAR 的 ZIP 结构无法解析，文件可能已损坏"
	case serverJarReasonSuspiciousEntry:
		return "服务端 JAR 含有越界或异常条目名"
	default:
		return "服务端 JAR 完整性校验失败"
	}
}

func auditServerJarMagic(header, tail []byte) (bool, bool) {
	zipHeader := len(header) >= serverJarHeaderBytes &&
		header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4
	zipCentral := false
	for i := len(tail) - 22; i >= 0; i-- {
		if tail[i] == 'P' && tail[i+1] == 'K' && tail[i+2] == 5 && tail[i+3] == 6 {
			zipCentral = true
			break
		}
	}
	return zipHeader, zipCentral
}

func suspiciousServerJarEntry(name string) bool {
	if name == "" {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if strings.Contains(name, "\\") {
		return true
	}
	if len(name) >= 2 && name[1] == ':' {
		return true
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

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
