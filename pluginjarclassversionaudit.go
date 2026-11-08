package main

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pjvMaxFindings = 14
	pjvMaxJars     = 512
	pjvMaxJarSize  = 256 * 1024 * 1024
	pjvMaxEntries  = 20000
	pjvMaxClasses  = 4096
	pjvMaxMajor    = 68
	pjvMiss        = "plugin-dir-missing"
	pjvRead        = "plugin-dir-unreadable"
	pjvLink        = "plugin-dir-symlink"
	pjvJarLink     = "plugin-jar-symlink"
	pjvJarOpen     = "plugin-jar-unreadable"
	pjvJarSize     = "plugin-jar-oversized"
	pjvBadMagic    = "plugin-class-bad-magic"
	pjvTooNew      = "plugin-class-version-high"
	pjvBadVersion  = "plugin-class-version-invalid"
)

type PjvFinding struct {
	Jar      string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type PjvAudit struct {
	ServerDir string
	Jars      int
	Classes   int
	MaxMajor  int
	Findings  []PjvFinding
}

func (a *PjvAudit) add(jar, entry, reason, detail string, blocking bool) {
	if len(a.Findings) >= pjvMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjvFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PjvAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjvAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjvAudit) Describe() string {
	return describeAuditFindings(fmt.Sprintf("插件字节码版本正常，%d 个 jar，%d 个 class，最高 major %d", a.Jars, a.Classes, a.MaxMajor), a.Findings, 8,
		func(f PjvFinding) []string {
			return []string{f.Reason, f.Entry}
		},
		func(f PjvFinding) string {
			return f.Reason
		})
}

func pjvClassHeader(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".class")
}

func AuditPluginClassVersion(serverDir string) *PjvAudit {
	a := &PjvAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", "", pjvMiss, "未配置服务器目录", false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", "", pjvMiss, "缺少插件目录", false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", "", pjvRead, err.Error(), true)
		return a
	}
	if link {
		a.add("plugins", "", pjvLink, "插件目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", "", pjvRead, "无法读取插件目录", true)
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
			a.add(name, "", pjvJarOpen, err.Error(), true)
			continue
		}
		if link {
			a.add(name, "", pjvJarLink, "jar 是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, "", pjvJarOpen, "jar 无法访问", true)
			continue
		}
		if info.Size() > pjvMaxJarSize {
			a.add(name, "", pjvJarSize, fmt.Sprintf("jar %d 字节超过上限", info.Size()), false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, "", pjvJarOpen, "jar 不是合法 zip", true)
			continue
		}

		count := 0
		for _, file := range archive.File {
			if !pjvClassHeader(file.Name) {
				continue
			}
			if count >= pjvMaxClasses {
				break
			}
			count++
			a.Classes++

			rc, err := file.Open()
			if err != nil {
				a.add(name, file.Name, pjvJarOpen, "无法读取条目内容", true)
				break
			}
			head := make([]byte, 8)
			n, _ := rc.Read(head)
			rc.Close()

			if n < 8 || string(head[:4]) != "\xca\xfe\xba\xbe" {
				a.add(name, file.Name, pjvBadMagic, "class 文件头不是 CAFEBABE", true)
				continue
			}
			major := binary.BigEndian.Uint16(head[6:8])
			if major < 45 {
				a.add(name, file.Name, pjvBadVersion, fmt.Sprintf("class major %d 低于下限 45", major), true)
				continue
			}
			if int(major) > a.MaxMajor {
				a.MaxMajor = int(major)
			}
			if major > pjvMaxMajor {
				a.add(name, file.Name, pjvTooNew, fmt.Sprintf("class major %d 高于上限 %d", major, pjvMaxMajor), false)
			}
		}
		archive.Close()
	}

	if a.Jars > pjvMaxJars {
		a.add("plugins", "", pjvTooNew, fmt.Sprintf("jar 数量 %d 超过上限", a.Jars), false)
	}
	return a
}
