package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pnhMaxFindings = 14
	pnhMaxJars     = 512
	pnhMaxJarSize  = 256 * 1024 * 1024
	pnhMaxEntries  = 20000
	pnhMiss        = "plugin-dir-missing"
	pnhRead        = "plugin-dir-unreadable"
	pnhLink        = "plugin-dir-symlink"
	pnhJarLink     = "plugin-jar-symlink"
	pnhJarOpen     = "plugin-jar-unreadable"
	pnhJarSize     = "plugin-jar-oversized"
	pnhNative      = "plugin-native-binary"
	pnhScript      = "plugin-exec-script"
	pnhTraversal   = "plugin-entry-traversal"
	pnhTooMany     = "plugin-jar-count-high"
)

var pnhNativeExt = map[string]bool{
	".dll": true, ".so": true, ".dylib": true, ".exe": true, ".sys": true, ".dll64": true, ".node": true,
}

var pnhScriptExt = map[string]bool{
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".sh": true,
}

type PnhFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Blocking bool
}

type PnhAudit struct {
	ServerDir string
	Jars      int
	Natives   int
	Findings  []PnhFinding
}

func (a *PnhAudit) add(jar, entry, reason string, blocking bool) {
	if len(a.Findings) >= pnhMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PnhFinding{Jar: jar, Entry: entry, Reason: reason, Blocking: blocking})
}

func (a *PnhAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PnhAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PnhAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件归档通过检查，共 %d 个 jar，未发现内嵌原生二进制", a.Jars)
	}
	sorted := make([]PnhFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Entry < sorted[j].Entry
	})
	parts := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= 8 {
			parts = append(parts, fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		parts = append(parts, f.Reason)
	}
	return strings.Join(parts, "；")
}

func pnhExt(name string) string {
	return strings.ToLower(filepath.Ext(name))
}

func AuditPluginNativeExtract(serverDir string) *PnhAudit {
	a := &PnhAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", "", pnhMiss, false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", "", pnhMiss, false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", "", pnhRead, true)
		return a
	}
	if link {
		a.add("plugins", "", pnhLink, true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", "", pnhRead, true)
		return a
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		a.Jars++
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(name, "", pnhJarOpen, true)
			continue
		}
		if link {
			a.add(name, "", pnhJarLink, true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, "", pnhJarOpen, true)
			continue
		}
		if info.Size() > pnhMaxJarSize {
			a.add(name, "", pnhJarSize, false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, "", pnhJarOpen, true)
			continue
		}
		count := 0
		for _, file := range archive.File {
			if count >= pnhMaxEntries {
				break
			}
			count++
			lower := strings.ToLower(file.Name)
			if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || strings.HasPrefix(file.Name, "\\") {
				a.add(name, file.Name, pnhTraversal, true)
				continue
			}
			if pnhNativeExt[lower[strings.LastIndex(lower, "."):]] {
				a.Natives++
				a.add(name, file.Name, pnhNative, true)
				continue
			}
			if pnhScriptExt[pnhExt(lower)] {
				a.add(name, file.Name, pnhScript, false)
			}
		}
		archive.Close()
	}

	if a.Jars > pnhMaxJars {
		a.add("plugins", "", pnhTooMany, false)
	}
	return a
}
