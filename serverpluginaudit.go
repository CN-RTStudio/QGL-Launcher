package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pluginReasonOK          = "ok"
	pluginReasonSymlink     = "symlink"
	pluginReasonNotDir      = "not-directory"
	pluginReasonTooLarge    = "too-large"
	pluginReasonBadZip      = "bad-zip"
	pluginReasonBadEntry    = "bad-entry"
	pluginReasonTooMany     = "too-many-entries"
	pluginReasonBadManifest = "bad-manifest"
	pluginReasonDuplicate   = "duplicate-name"
	pluginReasonExecutable  = "executable-file"
	pluginMaxCount          = 256
	pluginMaxBytes          = 64 << 20
	pluginMaxEntries        = 10000
	pluginMaxDirEntries     = 2048
	pluginMaxManifestBytes  = 256 << 10
	pluginMaxNameRunes      = 64
	pluginMaxClassChars     = 255
)

var pluginDangerousExt = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".com": true,
	".scr": true, ".ps1": true, ".sh": true, ".dll": true,
	".vbs": true, ".js": true, ".jar.exe": true,
}

type PluginFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerPluginAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Findings []PluginFinding
}

type pluginManifest struct {
	Name string
	Main string
}

func (a ServerPluginAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件目录共 %d 个 jar，未发现异常", a.Jars)
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func AuditServerPlugins(serverDir string) (ServerPluginAudit, error) {
	audit := ServerPluginAudit{Dir: filepath.Join(serverDir, "plugins")}
	info, err := os.Lstat(audit.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return audit, nil
		}
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonSymlink, Detail: "插件目录是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.IsDir() {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonNotDir, Detail: "插件路径不是目录", Blocking: true,
		})
		return audit, nil
	}
	entries, err := os.ReadDir(audit.Dir)
	if err != nil {
		return audit, err
	}
	if len(entries) > pluginMaxDirEntries {
		audit.Findings = append(audit.Findings, PluginFinding{
			Name: "plugins", Reason: pluginReasonTooMany,
			Detail: fmt.Sprintf("目录条目 %d 超过上限 %d", len(entries), pluginMaxDirEntries), Blocking: true,
		})
	}
	names := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(audit.Dir, name)
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return audit, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonSymlink, Detail: "插件条目是符号链接", Blocking: true,
			})
			continue
		}
		if entry.IsDir() {
			continue
		}
		lower := strings.ToLower(name)
		if pluginDangerousExt[lower] {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonExecutable, Detail: "插件目录出现可执行文件", Blocking: true,
			})
			continue
		}
		if !strings.HasSuffix(lower, ".jar") {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonBadEntry, Detail: "插件目录出现非 jar 文件", Blocking: false,
			})
			continue
		}
		audit.Jars++
		if audit.Jars > pluginMaxCount {
			audit.Findings = append(audit.Findings, PluginFinding{
				Name: name, Reason: pluginReasonTooMany,
				Detail: fmt.Sprintf("jar 数量超过上限 %d", pluginMaxCount), Blocking: true,
			})
			continue
		}
		findings, manifest, err := auditPluginJar(path, name)
		if err != nil {
			return audit, err
		}
		audit.Findings = append(audit.Findings, findings...)
		if manifest.Name != "" {
			key := strings.ToLower(manifest.Name)
			if first, ok := names[key]; ok {
				audit.Findings = append(audit.Findings, PluginFinding{
					Name: name, Reason: pluginReasonDuplicate,
					Detail: fmt.Sprintf("插件名 %q 与 %s 重复", manifest.Name, first), Blocking: true,
				})
			} else {
				names[key] = name
			}
		}
	}
	sort.SliceStable(audit.Findings, func(i, j int) bool { return audit.Findings[i].Name < audit.Findings[j].Name })
	return audit, nil
}
