package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a IconAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f IconFinding) bool { return f.Blocking }, func(f IconFinding) bool { return !f.Blocking && f.Reason != iconReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *IconAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, iconMaxFindings, IconFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func iconPixelBudget(data []byte) (int, int, int, bool) {
	offset := 8
	width := 0
	height := 0
	idat := 0
	for offset+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		kind := string(data[offset+4 : offset+8])
		if offset+12+length > len(data) {
			return 0, 0, 0, false
		}
		body := data[offset+8 : offset+8+length]
		switch kind {
		case "IHDR":
			if len(body) < 13 {
				return 0, 0, 0, false
			}
			width = int(binary.BigEndian.Uint32(body[0:4]))
			height = int(binary.BigEndian.Uint32(body[4:8]))
		case "IDAT":
			idat += len(body)
		case "IEND":
			return width, height, idat, width > 0 && height > 0
		}
		offset += 12 + length
	}
	return 0, 0, 0, false
}

func AuditServerIcon(serverDir string) IconAudit {
	audit := IconAudit{Dir: serverDir}
	for _, name := range iconCandidates {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		audit.Files = append(audit.Files, name)
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(name, iconReasonSymlink, "图标是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(name, iconReasonUnreadable, "图标不是普通文件", true)
			continue
		}
		if info.Size() > iconMaxFileBytes {
			audit.add(name, iconReasonTooLarge, "图标文件超过预算", true)
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.add(name, iconReasonUnreadable, "图标不可读", true)
			continue
		}
		before := len(audit.Findings)
		iconCheckPNG(&audit, name, data)
		if len(audit.Findings) == before && strings.HasSuffix(name, ".png") {
			if width, height, idat, ok := iconPixelBudget(data); ok {
				if width*height*4 > 0 && idat*iconInflateLimit < width*height*4 {
					audit.add(name, iconReasonInflateBomb, "压缩数据与解码体积比例异常", true)
				}
			}
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", iconReasonOK, "未配置服务器图标", false)
	}
	return audit
}
