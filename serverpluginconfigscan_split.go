package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func spxScanPluginConfigs(serverDir string) *spxScanResult {
	result := &spxScanResult{}
	pluginsDir := filepath.Join(serverDir, "plugins")
	info, err := os.Lstat(pluginsDir)
	if err != nil {
		return result
	}
	if info.Mode()&os.ModeSymlink != 0 {
		result.addNote("plugins", spxReasonSymlink, "插件目录为符号链接，配置来源不可信", true)
		return result
	}
	if !info.IsDir() {
		result.addNote("plugins", spxReasonBadFile, "插件路径不是目录", false)
		return result
	}

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		result.addNote("plugins", spxReasonUnread, "插件目录不可读", false)
		return result
	}
	if len(entries) > spxMaxPluginDirs {
		result.addNote("plugins", spxReasonTooMany, fmt.Sprintf("插件条目 %d 个，超过 %d", len(entries), spxMaxPluginDirs), false)
	}

	names := spxCandidateNames()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(pluginsDir, entry.Name())
		dirInfo, derr := os.Lstat(dir)
		if derr != nil {
			continue
		}
		if dirInfo.Mode()&os.ModeSymlink != 0 {
			result.addNote(filepath.Join("plugins", entry.Name()), spxReasonSymlink, "插件目录为符号链接", true)
			continue
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			fileInfo, ferr := os.Lstat(path)
			if ferr != nil {
				continue
			}
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				result.addNote(filepath.Join("plugins", entry.Name(), name), spxReasonSymlink, "插件配置为符号链接", true)
				continue
			}
			if !fileInfo.Mode().IsRegular() {
				result.addNote(filepath.Join("plugins", entry.Name(), name), spxReasonBadFile, "插件配置不是普通文件", false)
				continue
			}
			if fileInfo.Size() > spxMaxConfigBytes {
				result.addNote(filepath.Join("plugins", entry.Name(), name), spxReasonTooLarge, fmt.Sprintf("插件配置超过 %d 字节", spxMaxConfigBytes), true)
				continue
			}
			data, rerr := readBoundedFile(path, spxMaxConfigBytes)
			if rerr != nil {
				if errors.Is(rerr, errLocalFileTooLarge) {
					result.addNote(filepath.Join("plugins", entry.Name(), name), spxReasonTooLarge, "插件配置读取超限", true)
					continue
				}
				result.addNote(filepath.Join("plugins", entry.Name(), name), spxReasonUnread, "插件配置不可读", false)
				continue
			}
			rel := filepath.Join("plugins", entry.Name(), name)
			result.Configs = append(result.Configs, spxConfig{Rel: rel, Text: string(data), Flat: cfgFlattenYAML(string(data))})
		}
	}
	sort.Slice(result.Configs, func(i, j int) bool { return result.Configs[i].Rel < result.Configs[j].Rel })
	return result
}
