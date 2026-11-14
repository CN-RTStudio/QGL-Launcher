package main

import (
	"archive/zip"
	"fmt"
	"strings"
)

func isManifestModJar(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, ".jar.disabled")
}

func (audit *ModManifestAudit) scanJar(fileName, jarPath string, modIDs map[string]string) {
	reader, err := zip.OpenReader(jarPath)
	if err != nil {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: fileName, Reason: modManifestReasonBadZip,
			Detail: "无法作为 zip 打开", Blocking: true,
		})
		return
	}
	defer reader.Close()
	if len(reader.File) == 0 {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: fileName, Reason: modManifestReasonEmptyArchive,
			Detail: "压缩包内没有任何条目", Blocking: true,
		})
		return
	}
	seen := map[string]bool{}
	for _, entry := range reader.File {
		audit.Entries++
		if audit.Entries > modManifestMaxEntries {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Reason: modManifestReasonTooManyEntries,
				Detail: "累计条目数超过上限", Blocking: true,
			})
			return
		}
		if suspiciousServerJarEntry(entry.Name) {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonSuspiciousEntry,
				Detail: "条目路径可疑", Blocking: true,
			})
		}
		if seen[entry.Name] {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonDuplicateEntry,
				Detail: "压缩包内条目重名，解压行为不确定", Blocking: true,
			})
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > modManifestMaxEntryBytes {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonEntryTooLarge,
				Detail: fmt.Sprintf("解压后 %d 字节超过上限", entry.UncompressedSize64), Blocking: true,
			})
		} else if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > modManifestMaxRatio {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: fileName, Entry: entry.Name, Reason: modManifestReasonBombRatio,
				Detail: "压缩比超过阈值", Blocking: true,
			})
		}
		if id, ok := modIDFromEntry(entry); ok {
			if id == "" {
				audit.Findings = append(audit.Findings, ModManifestFinding{
					File: fileName, Entry: entry.Name, Reason: modManifestReasonBadMetadata,
					Detail: "模组元数据无法解析出 id", Blocking: false,
				})
				continue
			}
			if previous, exists := modIDs[id]; exists {
				audit.Findings = append(audit.Findings, ModManifestFinding{
					File: fileName, Entry: id, Reason: modManifestReasonDuplicateID,
					Detail: fmt.Sprintf("id %q 与 %s 冲突", id, previous), Blocking: false,
				})
				continue
			}
			modIDs[id] = fileName
		}
	}
}
