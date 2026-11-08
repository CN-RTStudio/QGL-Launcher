package main

import (
	"archive/zip"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	pjpMaxFindings  = 16
	pjpMaxJars      = 512
	pjpMaxJarSize   = 256 * 1024 * 1024
	pjpMaxServices  = 2048
	pjpMaxProviders = 256
	pjpMaxFileSize  = 128 * 1024
	pjpMiss         = "plugin-dir-missing"
	pjpRead         = "plugin-dir-unreadable"
	pjpLink         = "plugin-dir-symlink"
	pjpJarLink      = "plugin-jar-symlink"
	pjpJarOpen      = "plugin-jar-unreadable"
	pjpJarSize      = "plugin-jar-oversized"
	pjpBadService   = "plugin-service-name-invalid"
	pjpBadProvider  = "plugin-service-provider-invalid"
	pjpMissing      = "plugin-service-provider-missing"
	pjpDuplicate    = "plugin-service-provider-duplicate"
	pjpEmpty        = "plugin-service-empty"
)

var pjpFqnPattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

type PjpFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type PjpAudit struct {
	ServerDir string
	Jars      int
	Services  int
	Providers int
	Findings  []PjpFinding
}

func (a *PjpAudit) add(jar, entry, reason, detail string, blocking bool) {
	if len(a.Findings) >= pjpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjpFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PjpAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjpAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjpAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件服务声明合法，%d 个 jar，%d 个服务文件，%d 个提供者", a.Jars, a.Services, a.Providers)
	}
	sorted := make([]PjpFinding, len(a.Findings))
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

func pjpClassNameSet(files []*zip.File) map[string]bool {
	classes := make(map[string]bool, len(files))
	for _, f := range files {
		name := f.Name
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		classes[strings.TrimSuffix(name, ".class")] = true
	}
	return classes
}

func pjpProviderPresent(classes map[string]bool, provider string) bool {
	path := strings.ReplaceAll(provider, ".", "/")
	if classes[path] {
		return true
	}
	dollar := strings.Index(path, "$")
	if dollar < 0 {
		return false
	}
	outer := path[:dollar]
	return classes[outer]
}

func AuditPluginServiceProviders(serverDir string) *PjpAudit {
	a := &PjpAudit{ServerDir: serverDir}
	walk := walkPluginJars(serverDir, pjpMaxJarSize, pluginJarWalkReasons{
		Missing: pjpMiss,
		Read:    pjpRead,
		DirLink: pjpLink,
		JarLink: pjpJarLink,
		JarOpen: pjpJarOpen,
		JarSize: pjpJarSize,
	}, func(name string, archive *zip.ReadCloser) {
		classes := pjpClassNameSet(archive.File)
		for _, file := range archive.File {
			if a.Services >= pjpMaxServices {
				break
			}
			entryName := file.Name
			if !strings.HasPrefix(entryName, "META-INF/services/") || strings.HasSuffix(entryName, "/") {
				continue
			}
			a.Services++
			service := strings.TrimPrefix(entryName, "META-INF/services/")
			if !pjpFqnPattern.MatchString(service) {
				a.add(name, entryName, pjpBadService, "服务接口名不合法", true)
				continue
			}

			if file.UncompressedSize64 > uint64(pjpMaxFileSize) {
				a.add(name, entryName, pjpBadService, "服务文件体积超过上限", false)
				continue
			}
			rc, err := file.Open()
			if err != nil {
				a.add(name, entryName, pjpJarOpen, "无法读取服务文件", true)
				break
			}
			body, err := io.ReadAll(io.LimitReader(rc, pjpMaxFileSize))
			rc.Close()
			if err != nil {
				a.add(name, entryName, pjpJarOpen, "读取服务文件失败", true)
				break
			}

			text := strings.TrimPrefix(string(body), "\ufeff")
			seen := make(map[string]bool)
			count := 0
			empty := true
			for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				empty = false
				if idx := strings.Index(line, "#"); idx >= 0 {
					line = strings.TrimSpace(line[:idx])
				}
				if line == "" {
					continue
				}
				count++
				if count > pjpMaxProviders {
					break
				}
				a.Providers++
				if !pjpFqnPattern.MatchString(line) {
					a.add(name, entryName, pjpBadProvider, "提供者名不合法 "+line, true)
					continue
				}
				if seen[line] {
					a.add(name, entryName, pjpDuplicate, "提供者重复声明 "+line, false)
					continue
				}
				seen[line] = true
				if !pjpProviderPresent(classes, line) {
					a.add(name, entryName, pjpMissing, "缺少提供者实现 "+line, false)
				}
			}
			if empty {
				a.add(name, entryName, pjpEmpty, "服务文件没有声明任何提供者", false)
			}
		}
	})
	a.Jars = walk.Jars
	for _, issue := range walk.Issues {
		a.add(issue.Jar, issue.Entry, issue.Reason, issue.Detail, issue.Blocking)
	}
	if a.Jars > pjpMaxJars {
		a.add("plugins", "", pjpJarSize, fmt.Sprintf("jar 数量 %d 超过上限", a.Jars), false)
	}
	return a
}
