package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func (audit *RegionAudit) inspectRegion(dir, name string) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonNotRegular, Detail: "无法读取元数据", Blocking: true,
		})
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonSymlink, Detail: "区域文件是符号链接", Blocking: true,
		})
		return
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonNotRegular, Detail: "区域文件不是普通文件", Blocking: true,
		})
		return
	}
	if info.Size() < regionHeaderBytes {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonShortHeader,
			Detail: fmt.Sprintf("文件仅 %d 字节，缺少完整头部", info.Size()), Blocking: true,
		})
		return
	}
	if info.Size() > regionMaxBytes {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonTooLarge,
			Detail: fmt.Sprintf("文件 %d 字节超过上限", info.Size()), Blocking: true,
		})
		return
	}
	file, err := os.Open(path)
	if err != nil {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonNotRegular, Detail: "打开失败", Blocking: true,
		})
		return
	}
	defer file.Close()
	header := make([]byte, regionHeaderBytes)
	if _, err := io.ReadFull(file, header); err != nil {
		audit.Findings = append(audit.Findings, RegionFinding{
			Region: path, Reason: regionReasonShortHeader, Detail: "头部读取不完整", Blocking: true,
		})
		return
	}
	totalSectors := info.Size() / regionSectorBytes
	for index := 0; index < regionSlotCount; index++ {
		raw := header[index*4 : index*4+4]
		sector := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
		count := int(raw[3])
		if sector == 0 && count == 0 {
			continue
		}
		audit.Chunks++
		if count == 0 || sector < 2 {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: path, Chunk: index, Reason: regionReasonBadOffset,
				Detail: fmt.Sprintf("偏移 %d 扇区长度 %d 非法", sector, count), Blocking: true,
			})
			continue
		}
		if int64(sector+count) > totalSectors {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: path, Chunk: index, Reason: regionReasonOutOfRange,
				Detail: fmt.Sprintf("扇区范围 %d..%d 超出文件 %d 扇区", sector, sector+count, totalSectors), Blocking: true,
			})
			continue
		}
		lengthBuf := make([]byte, 4)
		offset := int64(sector) * regionSectorBytes
		if _, err := file.ReadAt(lengthBuf, offset); err != nil {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: path, Chunk: index, Reason: regionReasonBadLength,
				Detail: "分块长度字段读取失败", Blocking: true,
			})
			continue
		}
		length := binary.BigEndian.Uint32(lengthBuf)
		if length == 0 || int64(length) > int64(count)*regionSectorBytes-4 {
			audit.Findings = append(audit.Findings, RegionFinding{
				Region: path, Chunk: index, Reason: regionReasonBadLength,
				Detail: fmt.Sprintf("分块声明长度 %d 超出扇区容量", length), Blocking: true,
			})
		}
	}
}
