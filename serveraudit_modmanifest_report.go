package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
