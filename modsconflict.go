package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type modConflict struct {
	ModID string
	Files []string
}

const modsMetaMaxBytes = 256 * 1024

func modsReadZipEntry(r *zip.ReadCloser, name string, limit int64) string {
	for _, f := range r.File {
		if !strings.EqualFold(f.Name, name) {
			continue
		}
		if f.UncompressedSize64 > uint64(limit) {
			return ""
		}
		rc, err := f.Open()
		if err != nil {
			return ""
		}
		defer rc.Close()
		body, err := io.ReadAll(io.LimitReader(rc, limit))
		if err != nil {
			return ""
		}
		return string(body)
	}
	return ""
}

func modsMetaValue(text string, key string) string {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, key))
		if !strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, ":") {
			continue
		}
		value := strings.TrimSpace(rest[1:])
		value = strings.Trim(value, "\"'")
		if value != "" {
			return value
		}
	}
	return ""
}

func modIDFromJar(path string) string {
	r, err := zip.OpenReader(path)
	if err != nil {
		return ""
	}
	defer r.Close()
	if body := modsReadZipEntry(r, "fabric.mod.json", modsMetaMaxBytes); body != "" {
		if id := modsMetaValue(body, "\"id\""); id != "" {
			return strings.ToLower(id)
		}
	}
	for _, name := range []string{"META-INF/mods.toml", "META-INF/neoforge.mods.toml"} {
		body := modsReadZipEntry(r, name, modsMetaMaxBytes)
		if body == "" {
			continue
		}
		if id := modsMetaValue(body, "modId"); id != "" {
			return strings.ToLower(id)
		}
	}
	if body := modsReadZipEntry(r, "mcmod.info", modsMetaMaxBytes); body != "" {
		if id := modsMetaValue(body, "\"modid\""); id != "" {
			return strings.ToLower(id)
		}
	}
	return ""
}

func detectModConflicts(modsDir string) ([]modConflict, error) {
	entries, err := os.ReadDir(modsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 mods 目录失败: %w", err)
	}
	byID := make(map[string][]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		full := filepath.Join(modsDir, name)
		info, statErr := os.Lstat(full)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() <= 0 || info.Size() > 512<<20 {
			continue
		}
		id := modIDFromJar(full)
		if id == "" {
			continue
		}
		byID[id] = append(byID[id], name)
	}
	var conflicts []modConflict
	for id, files := range byID {
		if len(files) < 2 {
			continue
		}
		sort.Strings(files)
		conflicts = append(conflicts, modConflict{ModID: id, Files: files})
	}
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].ModID < conflicts[j].ModID })
	return conflicts, nil
}

func modsConflictSummary(conflicts []modConflict) string {
	if len(conflicts) == 0 {
		return "未发现重复 modId"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "发现 %d 组重复 modId:", len(conflicts))
	for _, c := range conflicts {
		fmt.Fprintf(&b, " %s(%s)", c.ModID, strings.Join(c.Files, "/"))
	}
	return b.String()
}
