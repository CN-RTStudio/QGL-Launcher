package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

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

func modIDFromEntry(entry *zip.File) (string, bool) {
	name := strings.ToLower(entry.Name)
	base := filepath.Base(name)
	switch {
	case base == "fabric.mod.json", base == "quilt.mod.json":
	case base == "mods.toml" && strings.Contains(name, "meta-inf/"):
	case base == "mcmod.info":
	default:
		return "", false
	}
	if entry.UncompressedSize64 > uint64(modManifestMaxMetadataBytes) {
		return "", true
	}
	reader, err := entry.Open()
	if err != nil {
		return "", true
	}
	defer reader.Close()
	data := make([]byte, 0, modManifestMaxMetadataBytes)
	buf := make([]byte, 4096)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if int64(len(data)) > modManifestMaxMetadataBytes {
				return "", true
			}
		}
		if readErr != nil {
			break
		}
	}
	return extractModID(base, data), true
}

func extractModID(base string, data []byte) string {
	switch base {
	case "fabric.mod.json", "quilt.mod.json":
		var payload struct {
			ID    string `json:"id"`
			Quilt struct {
				ID string `json:"id"`
			} `json:"quilt_loader"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return ""
		}
		if strings.TrimSpace(payload.ID) != "" {
			return strings.TrimSpace(payload.ID)
		}
		return strings.TrimSpace(payload.Quilt.ID)
	case "mods.toml":
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "modId") {
				_, value, _, ok := splitPropertyPair(trimmed)
				if ok {
					return strings.Trim(strings.TrimSpace(value), "\"'")
				}
			}
		}
	case "mcmod.info":
		var payload []struct {
			ModID string `json:"modid"`
		}
		if err := json.Unmarshal(data, &payload); err != nil || len(payload) == 0 {
			return ""
		}
		return strings.TrimSpace(payload[0].ModID)
	}
	return ""
}
