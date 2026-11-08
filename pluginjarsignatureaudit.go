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
	pjsMaxFindings = 14
	pjsMaxJars     = 512
	pjsMaxJarSize  = 256 * 1024 * 1024
	pjsMaxEntries  = 20000
	pjsMaxSigners  = 16
	pjsMiss        = "plugin-dir-missing"
	pjsRead        = "plugin-dir-unreadable"
	pjsLink        = "plugin-dir-symlink"
	pjsJarLink     = "plugin-jar-symlink"
	pjsJarOpen     = "plugin-jar-unreadable"
	pjsJarSize     = "plugin-jar-oversized"
	pjsUnsigned    = "plugin-jar-unsigned"
	pjsPartial     = "plugin-signature-incomplete"
	pjsTooMany     = "plugin-jar-count-high"
)

type PjsFinding struct {
	Jar      string
	Reason   string
	Detail   string
	Blocking bool
}

type PjsAudit struct {
	ServerDir string
	Jars      int
	Signed    int
	Findings  []PjsFinding
}

func (a *PjsAudit) add(jar, reason, detail string, blocking bool) {
	if len(a.Findings) >= pjsMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PjsFinding{Jar: jar, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PjsAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *PjsAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *PjsAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件签名检查通过，%d 个 jar，其中 %d 个已签名", a.Jars, a.Signed)
	}
	sorted := make([]PjsFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Jar < sorted[j].Jar
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

func pjsSignatureEntry(name string) (kind string, ok bool) {
	lower := strings.ToLower(name)
	base := lower[strings.LastIndex(lower, "/")+1:]
	if !strings.HasPrefix(lower, "meta-inf/") {
		return "", false
	}
	if strings.HasSuffix(base, ".rsa") || strings.HasSuffix(base, ".dsa") || strings.HasSuffix(base, ".ec") {
		return "block", true
	}
	if strings.HasSuffix(base, ".sf") {
		return "sf", true
	}
	if base == "manifest.mf" {
		return "manifest", true
	}
	return "", false
}

func AuditPluginJarSignatures(serverDir string) *PjsAudit {
	a := &PjsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("plugins", pjsMiss, "未配置服务器目录", false)
		return a
	}

	dir := filepath.Join(serverDir, "plugins")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		a.add("plugins", pjsMiss, "缺少插件目录", false)
		return a
	}
	link, err := isSymlinkOrSpecial(dir)
	if err != nil {
		a.add("plugins", pjsRead, err.Error(), true)
		return a
	}
	if link {
		a.add("plugins", pjsLink, "插件目录是符号链接或特殊文件", true)
		return a
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		a.add("plugins", pjsRead, "无法读取插件目录", true)
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
			a.add(name, pjsJarOpen, err.Error(), true)
			continue
		}
		if link {
			a.add(name, pjsJarLink, "jar 是符号链接或特殊文件", true)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			a.add(name, pjsJarOpen, "jar 无法访问", true)
			continue
		}
		if info.Size() > pjsMaxJarSize {
			a.add(name, pjsJarSize, fmt.Sprintf("jar %d 字节超过上限 %d", info.Size(), int64(pjsMaxJarSize)), false)
			continue
		}

		archive, err := zip.OpenReader(path)
		if err != nil {
			a.add(name, pjsJarOpen, "jar 不是合法 zip", true)
			continue
		}

		hasBlock := false
		hasSF := false
		signers := 0
		count := 0
		for _, file := range archive.File {
			if count >= pjsMaxEntries {
				break
			}
			count++
			kind, ok := pjsSignatureEntry(file.Name)
			if !ok {
				continue
			}
			switch kind {
			case "block":
				hasBlock = true
				signers++
			case "sf":
				hasSF = true
			}
		}
		archive.Close()

		if !hasBlock && !hasSF {
			a.add(name, pjsUnsigned, "缺少 META-INF 签名块", false)
			continue
		}
		if hasBlock != hasSF {
			a.add(name, pjsPartial, "签名块与签名文件不配套", true)
			continue
		}
		if signers > pjsMaxSigners {
			a.add(name, pjsPartial, fmt.Sprintf("签名者数量 %d 超过上限 %d", signers, pjsMaxSigners), false)
			continue
		}
		a.Signed++
	}

	if a.Jars > pjsMaxJars {
		a.add("plugins", pjsTooMany, fmt.Sprintf("jar 数量 %d 超过上限 %d", a.Jars, pjsMaxJars), false)
	}
	return a
}
