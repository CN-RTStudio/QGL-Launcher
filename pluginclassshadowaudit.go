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
	pcxMaxFindings  = 14
	pcxMaxJars      = 512
	pcxMaxJarSize   = 256 * 1024 * 1024
	pcxMaxEntries   = 20000
	pcxMaxEntryName = 512
	pcxMiss         = "plugin-dir-missing"
	pcxRead         = "plugin-dir-unreadable"
	pcxLink         = "plugin-dir-symlink"
	pcxJarLink      = "plugin-jar-symlink"
	pcxJarSize      = "plugin-jar-oversized"
	pcxJarOpen      = "plugin-jar-unreadable"
	pcxEntryName    = "plugin-entry-name-malformed"
	pcxShadow       = "plugin-class-shadowed"
	pcxTooMany      = "plugin-jar-count-high"
)

type PcxShadow struct {
	Class string
	A     string
	B     string
}

type PcxAudit struct {
	ServerDir string
	Jars      int
	Classes   int
	Findings  []string
	Shadows   []PcxShadow
}

func (a *PcxAudit) add(reason string) {
	if len(a.Findings) >= pcxMaxFindings {
		return
	}
	a.Findings = append(a.Findings, reason)
}

func (a *PcxAudit) Blocking() bool {
	for _, f := range a.Findings {
		switch f {
		case pcxLink, pcxJarLink, pcxJarOpen, pcxRead:
			return true
		}
	}
	return false
}

func (a *PcxAudit) HasWarnings() bool {
	return len(a.Findings) > 0 || len(a.Shadows) > 0
}

func (a *PcxAudit) Describe() string {
	if !a.HasWarnings() {
		return fmt.Sprintf("插件类图通过检查，共 %d 个 jar、%d 个类", a.Jars, a.Classes)
	}
	parts := make([]string, 0, len(a.Findings)+len(a.Shadows))
	parts = append(parts, a.Findings...)
	shadows := make([]string, 0, len(a.Shadows))
	for _, s := range a.Shadows {
		shadows = append(shadows, s.Class)
	}
	sort.Strings(shadows)
	for i, c := range shadows {
		if i >= 5 {
			parts = append(parts, fmt.Sprintf("…等 %d 个重复类", len(shadows)))
			break
		}
		parts = append(parts, pcxShadow+":"+c)
	}
	for i := len(parts); i > 12; i-- {
		parts = parts[:12]
	}
	return strings.Join(parts, "；")
}

func pcxEntryClass(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".class") && !strings.HasPrefix(name, "META-INF/")
}

func pcxEntryNameOK(name string) bool {
	if name == "" || len(name) > pcxMaxEntryName {
		return false
	}
	if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return false
	}
	return true
}

func AuditPluginClassShadow(serverDir string) *PcxAudit {
	a := &PcxAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(pcxMiss)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add(pcxMiss)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add(pcxRead)
		return a
	}
	if link {
		a.add(pcxLink)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add(pcxRead)
		return a
	}

	owners := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		a.Jars++
		path := filepath.Join(dir, name)
		link, err := isSymlinkOrSpecial(path)
		if err != nil {
			a.add(pcxJarOpen)
			continue
		}
		if link {
			a.add(pcxJarLink)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(pcxJarOpen)
			continue
		}
		if info.Size() > pcxMaxJarSize {
			a.add(pcxJarSize)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(pcxJarOpen)
			continue
		}
		count := 0
		dupRecorded := 0
		for _, file := range archive.File {
			if count >= pcxMaxEntries {
				break
			}
			count++
			if !pcxEntryNameOK(file.Name) {
				a.add(pcxEntryName)
				continue
			}
			if !pcxEntryClass(file.Name) {
				continue
			}
			a.Classes++
			if prev, ok := owners[file.Name]; ok && prev != name {
				if dupRecorded >= 3 {
					continue
				}
				dupRecorded++
				if len(a.Shadows) < pcxMaxFindings {
					a.Shadows = append(a.Shadows, PcxShadow{Class: file.Name, A: prev, B: name})
				}
				continue
			}
			owners[file.Name] = name
		}
		archive.Close()
	}

	if a.Jars > pcxMaxJars {
		a.add(pcxTooMany)
	}
	return a
}
