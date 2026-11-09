package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
