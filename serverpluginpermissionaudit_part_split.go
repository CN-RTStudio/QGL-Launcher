package main

import (
	"os"
	"path/filepath"
	"strings"
)

func plugPermInspect(audit *PluginPermissionAudit, path, display string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置不是普通文件", true)
		return
	}
	if info.Size() > plugPermMaxFileBytes {
		audit.add(display, 0, plugPermReasonTooLarge, "插件配置超过大小上限", true)
		return
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置不可读", true)
		return
	}
	audit.Files++
	plugPermScanFile(audit, display, data)
}

func AuditServerPluginPermissions(serverDir string) PluginPermissionAudit {
	audit := PluginPermissionAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", 0, plugPermReasonMissing, "服务器目录不存在", true)
		return audit
	}
	pluginsDir := filepath.Join(serverDir, "plugins")
	if _, err := os.ReadDir(pluginsDir); err != nil {
		audit.add("plugins", 0, plugPermReasonMissing, "插件目录不存在或不可读", false)
		return audit
	}
	visited := 0
	var walk func(dir, display string, depth int)
	walk = func(dir, display string, depth int) {
		if depth > plugPermMaxDepth || visited >= plugPermMaxFiles {
			return
		}
		list, err := os.ReadDir(dir)
		if err != nil {
			audit.add(display, 0, plugPermReasonUnreadable, "插件子目录不可读", false)
			return
		}
		for _, entry := range list {
			if visited >= plugPermMaxFiles {
				audit.add(display, 0, plugPermReasonTooMany, "插件配置文件数量超过上限", true)
				return
			}
			name := entry.Name()
			child := filepath.Join(dir, name)
			if entry.IsDir() {
				walk(child, filepath.Join(display, name), depth+1)
				continue
			}
			if !plugPermFileNames[strings.ToLower(name)] {
				continue
			}
			visited++
			plugPermInspect(&audit, child, filepath.Join(display, name))
		}
	}
	walk(pluginsDir, "plugins", 1)
	if len(audit.Findings) == 0 {
		audit.add("", 0, plugPermReasonOK, "插件配置未声明通配权限", false)
	}
	return audit
}
