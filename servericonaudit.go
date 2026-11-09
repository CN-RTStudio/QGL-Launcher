package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	sicMaxFile      = 256 * 1024
	sicMaxSide      = 1024
	sicExpectedSide = 64
	sicMaxFindings  = 24
	sicReasonMiss   = "missing"
	sicReasonLink   = "symlink"
	sicReasonLarge  = "too-large"
	sicReasonRead   = "unreadable"
	sicReasonMagic  = "not-png"
	sicReasonShape  = "invalid-ihdr"
	sicReasonSide   = "oversized-icon"
	sicReasonSize   = "non-standard-size"
)

type IconFileFinding = auditFinding

type IconFileAudit struct {
	ServerDir string
	Findings  []IconFileFinding
}

func (a *IconFileAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sicMaxFindings, IconFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *IconFileAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f IconFileFinding) bool { return f.Blocking })
}

func (a *IconFileAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *IconFileAudit) Describe() string {
	return describeFileReasonDetail("服务器图标未发现风险", a.Findings, 12)
}

func AuditServerIconFile(serverDir string) *IconFileAudit {
	a := &IconFileAudit{ServerDir: serverDir}
	const rel = "server-icon.png"
	if serverDir == "" {
		a.add(".", sicReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sicReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sicReasonLink, "服务器图标为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sicMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sicReasonLarge, fmt.Sprintf("图标超过 %d 字节", sicMaxFile), true)
			return a
		}
		a.add(rel, sicReasonRead, "图标不可读", false)
		return a
	}
	if len(data) < 24 || !bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		a.add(rel, sicReasonMagic, "文件不是 PNG 图像", true)
		return a
	}
	if string(data[12:16]) != "IHDR" {
		a.add(rel, sicReasonShape, "缺少 IHDR 数据块", true)
		return a
	}
	width := int(binaryUint32(data[16:20]))
	height := int(binaryUint32(data[20:24]))
	if width <= 0 || height <= 0 || width > sicMaxSide || height > sicMaxSide {
		a.add(rel, sicReasonSide, fmt.Sprintf("图标尺寸 %dx%d 超出安全范围", width, height), true)
		return a
	}
	if width != sicExpectedSide || height != sicExpectedSide {
		a.add(rel, sicReasonSize, fmt.Sprintf("图标尺寸 %dx%d 不是 64x64", width, height), false)
	}
	return a
}

func binaryUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
