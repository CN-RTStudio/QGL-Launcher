package main

import (
	"archive/zip"
	"fmt"
	"path/filepath"
	"strings"
)

func mjmScanJar(a *ModJarManifestAudit, root, rel string, size int64) {
	path := filepath.Join(root, rel)
	reader, err := zip.OpenReader(path)
	if err != nil {
		a.add(rel, mjmReasonBadJar, "无法作为 ZIP/JAR 打开", false)
		return
	}
	defer reader.Close()
	if len(reader.File) > mjmMaxEntries {
		a.add(rel, mjmReasonEntryOverflow, fmt.Sprintf("条目数 %d 超过 %d", len(reader.File), mjmMaxEntries), false)
		return
	}
	found := false
	for _, entry := range reader.File {
		name := strings.ToLower(entry.Name)
		if name != "meta-inf/manifest.mf" {
			continue
		}
		found = true
		if entry.UncompressedSize64 > mjmMaxManifest {
			a.add(rel, mjmReasonManifestLarge, fmt.Sprintf("MANIFEST.MF 解压后 %d 字节", entry.UncompressedSize64), false)
			return
		}
		file, ferr := entry.Open()
		if ferr != nil {
			a.add(rel, mjmReasonBadJar, "MANIFEST.MF 无法读取", false)
			return
		}
		data := make([]byte, 0, mjmMaxManifest)
		buf := make([]byte, 4096)
		for {
			n, rerr := file.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				if len(data) > mjmMaxManifest {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		file.Close()
		mjmCheckManifest(a, rel, string(data))
		return
	}
	if !found {
		a.add(rel, mjmReasonMissing, "JAR 内无 META-INF/MANIFEST.MF", false)
	}
}

func mjmCheckManifest(a *ModJarManifestAudit, rel, text string) {
	if strings.TrimSpace(text) == "" {
		a.add(rel, mjmReasonBadJar, "MANIFEST.MF 为空", false)
		return
	}
	attrs := mjmParseManifest(text)
	for _, key := range []string{"premain-class", "agent-class", "launcher-agent-class"} {
		value, ok := attrs[key]
		if !ok || value == "" {
			continue
		}
		a.add(rel, mjmReasonAgent, key+"="+value, true)
	}
	if value, ok := attrs["class-path"]; ok {
		for _, entry := range mjmClassPathEntries(value) {
			if mjmUnsafeClassPathEntry(entry) {
				a.add(rel, mjmReasonClassPath, "Class-Path 指向外部路径: "+entry, true)
				break
			}
			if !strings.HasPrefix(entry, "META-INF/") && !strings.HasSuffix(strings.ToLower(entry), ".jar") {
				a.add(rel, mjmReasonClassPath, "Class-Path 条目不是归档内依赖: "+entry, false)
				break
			}
		}
	}
	if value, ok := attrs["main-class"]; ok {
		if strings.Contains(value, "..") || strings.Contains(value, "/") || strings.Contains(value, "\\") {
			a.add(rel, mjmReasonMainClass, "Main-Class 含路径写法: "+value, false)
		}
	}
}
