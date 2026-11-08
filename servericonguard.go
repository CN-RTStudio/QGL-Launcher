package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	iconReasonOK              = "ok"
	iconReasonMissing         = "missing"
	iconReasonUnreadable      = "unreadable"
	iconReasonTooLarge        = "too-large"
	iconReasonSymlink         = "symlink"
	iconReasonBadType         = "bad-type"
	iconReasonTruncated       = "truncated"
	iconReasonOversized       = "oversized"
	iconReasonNonstandardSize = "nonstandard-size"
	iconReasonBadChunk        = "bad-chunk"
	iconReasonTrailingData    = "trailing-data"
	iconReasonInflateBomb     = "inflate-bomb"
	iconReasonBadColorType    = "bad-color-type"

	iconMaxFileBytes = 512 << 10
	iconMaxDimension = 512
	iconMaxFindings  = 48
	iconInflateLimit = 2048
)

var iconCandidates = []string{"server-icon.png", filepath.Join("world", "icon.png")}

type IconFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type IconAudit struct {
	Dir      string
	Files    []string
	Findings []IconFinding
}

func (a IconAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a IconAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != iconReasonOK {
			return true
		}
	}
	return false
}

func (a IconAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == iconReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a IconAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现服务器图标"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a IconAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != iconReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *IconAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= iconMaxFindings {
		return
	}
	a.Findings = append(a.Findings, IconFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func iconChunkTypeValid(chunk [4]byte) bool {
	for _, ch := range chunk {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') {
			return false
		}
	}
	return true
}

func iconCheckPNG(audit *IconAudit, name string, data []byte) {
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		audit.add(name, iconReasonBadType, "文件不是 PNG 签名", true)
		return
	}
	offset := 8
	width := 0
	height := 0
	colorType := -1
	idatBytes := 0
	chunks := 0
	for offset+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		var chunk [4]byte
		copy(chunk[:], data[offset+4:offset+8])
		if !iconChunkTypeValid(chunk) {
			audit.add(name, iconReasonBadChunk, "PNG chunk 类型非法", true)
			return
		}
		if length < 0 || offset+12+length > len(data) {
			audit.add(name, iconReasonTruncated, "PNG chunk 越过文件边界", true)
			return
		}
		kind := string(chunk[:])
		body := data[offset+8 : offset+8+length]
		chunks++
		switch kind {
		case "IHDR":
			if len(body) < 13 {
				audit.add(name, iconReasonBadChunk, "IHDR 长度不足", true)
				return
			}
			if width == 0 {
				width = int(binary.BigEndian.Uint32(body[0:4]))
				height = int(binary.BigEndian.Uint32(body[4:8]))
				colorType = int(body[9])
				if width <= 0 || height <= 0 {
					audit.add(name, iconReasonBadChunk, "IHDR 尺寸为零", true)
					return
				}
				if width > iconMaxDimension || height > iconMaxDimension {
					audit.add(name, iconReasonOversized, fmt.Sprintf("图标尺寸 %dx%d 超过上限", width, height), true)
					return
				}
				if width != 64 || height != 64 {
					audit.add(name, iconReasonNonstandardSize, fmt.Sprintf("图标尺寸 %dx%d 非 64x64", width, height), false)
				}
				switch colorType {
				case 0, 2, 3, 4, 6:
				default:
					audit.add(name, iconReasonBadColorType, fmt.Sprintf("PNG 颜色类型 %d 非法", colorType), true)
					return
				}
			}
		case "IDAT":
			idatBytes += len(body)
		case "IEND":
			rest := len(data) - (offset + 12 + length)
			if rest > 0 {
				audit.add(name, iconReasonTrailingData, fmt.Sprintf("IEND 之后还有 %d 字节", rest), false)
			}
			return
		}
		offset += 12 + length
	}
	audit.add(name, iconReasonTruncated, "PNG 缺少 IEND 结束块", true)
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
