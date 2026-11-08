package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pjnMaxFindings = 14
	pjnMaxJars     = 512
	pjnMaxJarSize  = 256 * 1024 * 1024
	pjnMaxEntries  = 20000
	pjnMiss        = "plugin-dir-missing"
	pjnRead        = "plugin-dir-unreadable"
	pjnLink        = "plugin-dir-symlink"
	pjnJarLink     = "plugin-jar-symlink"
	pjnJarOpen     = "plugin-jar-unreadable"
	pjnJarSize     = "plugin-jar-oversized"
	pjnNested      = "plugin-embedded-jar"
	pjnTraversal   = "plugin-entry-traversal"
	pjnTooMany     = "plugin-jar-count-high"
)

type PjnFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Blocking bool
}

type PjnAudit struct {
	ServerDir string
	Jars      int
	Nested    int
	Findings  []PjnFinding
}

func (a *PjnAudit) add(jar, entry, reason string, blocking bool) {
	if len(a.Findings) >= pjnMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjnFinding{Jar: jar, Entry: entry, Reason: reason, Blocking: blocking})
}

func (a *PjnAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjnAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjnAudit) Describe() string {
	return describeAuditFindings(fmt.Sprintf("插件归档无嵌套包，共 %d 个 jar", a.Jars), a.Findings, 8,
		func(f PjnFinding) []string {
			return []string{f.Reason, f.Entry}
		},
		func(f PjnFinding) string {
			return f.Reason
		})
}

func pjnNestedEntry(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".jar") {
		return false
	}
	if strings.HasPrefix(lower, "meta-inf/") {
		return false
	}
	return true
}

func AuditPluginNestedJars(serverDir string) *PjnAudit {
	a := &PjnAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", "", pjnMiss, false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", "", pjnMiss, false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", "", pjnRead, true)
		return a
	}
	if link {
		a.add("plugins", "", pjnLink, true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", "", pjnRead, true)
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
			a.add(name, "", pjnJarOpen, true)
			continue
		}
		if link {
			a.add(name, "", pjnJarLink, true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, "", pjnJarOpen, true)
			continue
		}
		if info.Size() > pjnMaxJarSize {
			a.add(name, "", pjnJarSize, false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, "", pjnJarOpen, true)
			continue
		}
		count := 0
		for _, file := range archive.File {
			if count >= pjnMaxEntries {
				break
			}
			count++
			if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") || strings.HasPrefix(file.Name, "\\") {
				a.add(name, file.Name, pjnTraversal, true)
				continue
			}
			if pjnNestedEntry(file.Name) {
				a.Nested++
				a.add(name, file.Name, pjnNested, false)
			}
		}
		archive.Close()
	}

	if a.Jars > pjnMaxJars {
		a.add("plugins", "", pjnTooMany, false)
	}
	return a
}
