package main

import (
	"fmt"
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
