package main

import (
	"archive/zip"
	"os"
	"strings"
)

func packCheckZip(audit *DataPackAudit, name, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(name, dpReasonUnreadable, "数据包不可访问", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(name, dpReasonSymlink, "数据包是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(name, dpReasonUnreadable, "数据包不是普通文件", true)
		return
	}
	if info.Size() > dpMaxFileBytes {
		audit.add(name, dpReasonTooLarge, "数据包超过体积预算", true)
		return
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		audit.add(name, dpReasonBadZip, "数据包不是合法 zip", true)
		return
	}
	defer reader.Close()
	if len(reader.File) > dpMaxEntries {
		audit.add(name, dpReasonTooMany, "数据包条目数超过预算", true)
		return
	}
	seen := map[string]bool{}
	hasMeta := false
	for _, entry := range reader.File {
		if packEntryUnsafe(entry.Name) {
			audit.add(name, dpReasonEntryEscape, "条目路径可逃逸: "+packShorten(entry.Name), true)
			continue
		}
		lower := strings.ToLower(entry.Name)
		if seen[lower] {
			audit.add(name, dpReasonDuplicateName, "重复条目: "+packShorten(entry.Name), false)
		}
		seen[lower] = true
		if lower == "pack.mcmeta" {
			hasMeta = true
			if entry.UncompressedSize64 > dpMaxFileBytes {
				audit.add(name, dpReasonTooLarge, "pack.mcmeta 解压体积过大", true)
				continue
			}
			file, err := entry.Open()
			if err != nil {
				audit.add(name, dpReasonUnreadable, "pack.mcmeta 不可读", false)
				continue
			}
			data := make([]byte, 0, 64<<10)
			buf := make([]byte, 4096)
			for {
				n, readErr := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					if len(data) > dpMaxFileBytes {
						break
					}
				}
				if readErr != nil {
					break
				}
			}
			file.Close()
			packCheckMeta(audit, name, data)
		}
	}
	if !hasMeta {
		audit.add(name, dpReasonMissingMcmeta, "数据包缺少 pack.mcmeta", false)
	}
	if len(reader.File) == 0 {
		audit.add(name, dpReasonEmptyPack, "数据包为空 zip", false)
	}
}
