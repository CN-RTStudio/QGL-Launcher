package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	modManifestReasonOK              = "ok"
	modManifestReasonSymlink         = "symlink"
	modManifestReasonNotRegular      = "not-regular"
	modManifestReasonTooLarge        = "too-large"
	modManifestReasonBadZip          = "bad-zip"
	modManifestReasonTooManyEntries  = "too-many-entries"
	modManifestReasonEntryTooLarge   = "entry-too-large"
	modManifestReasonBombRatio       = "bomb-ratio"
	modManifestReasonSuspiciousEntry = "suspicious-entry"
	modManifestReasonDuplicateEntry  = "duplicate-entry"
	modManifestReasonBadMetadata     = "bad-metadata"
	modManifestReasonDuplicateID     = "duplicate-mod-id"
	modManifestReasonEmptyArchive    = "empty-archive"
	modManifestMaxJars               = 2000
	modManifestMaxJarBytes           = int64(512) << 20
	modManifestMaxEntries            = 20000
	modManifestMaxEntryBytes         = uint64(256) << 20
	modManifestMaxRatio              = 200
	modManifestMaxMetadataBytes      = int64(512) << 10
)

type ModManifestFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type ModManifestAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Entries  int
	Findings []ModManifestFinding
}

func (audit ModManifestAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f ModManifestFinding) bool { return f.Blocking })
}

func (audit ModManifestAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

func (audit ModManifestAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f ModManifestFinding) string { return f.Reason })
}

func (audit ModManifestAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "模组清单校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		entry := finding.Entry
		if entry == "" {
			entry = finding.File
		}
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", finding.File, entry, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func isManifestModJar(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") && !strings.HasSuffix(lower, ".jar.disabled")
}

func AuditServerModManifest(modsDir string) (ModManifestAudit, error) {
	audit := ModManifestAudit{Dir: modsDir}
	if strings.TrimSpace(modsDir) == "" {
		return audit, nil
	}
	info, err := os.Lstat(modsDir)
	if os.IsNotExist(err) {
		return audit, nil
	}
	if err != nil {
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonSymlink,
			Detail: "mods 目录本身是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, ModManifestFinding{
			File: modsDir, Reason: modManifestReasonNotRegular,
			Detail: "mods 路径不是目录", Blocking: true,
		})
		return audit, nil
	}

	entries, err := os.ReadDir(modsDir)
	if err != nil {
		return audit, err
	}
	modIDs := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !isManifestModJar(entry.Name()) {
			continue
		}
		if audit.Jars >= modManifestMaxJars {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: modsDir, Reason: modManifestReasonTooManyEntries,
				Detail: fmt.Sprintf("jar 数量超过 %d", modManifestMaxJars), Blocking: true,
			})
			break
		}
		audit.Jars++
		jarPath := filepath.Join(modsDir, entry.Name())
		jarInfo, statErr := os.Lstat(jarPath)
		if statErr != nil {
			return audit, statErr
		}
		if jarInfo.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonSymlink,
				Detail: "jar 是符号链接，实际内容可被外部替换", Blocking: true,
			})
			continue
		}
		if !jarInfo.Mode().IsRegular() {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonNotRegular,
				Detail: "jar 不是普通文件", Blocking: true,
			})
			continue
		}
		if jarInfo.Size() > modManifestMaxJarBytes {
			audit.Findings = append(audit.Findings, ModManifestFinding{
				File: entry.Name(), Reason: modManifestReasonTooLarge,
				Detail: fmt.Sprintf("jar 体积 %d 超过上限", jarInfo.Size()), Blocking: true,
			})
			continue
		}
		audit.scanJar(entry.Name(), jarPath, modIDs)
	}
	return audit, nil
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
