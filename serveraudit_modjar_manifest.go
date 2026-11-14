package main

import (
	"strings"
)

func mjmParseManifest(text string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var current string
	var builder strings.Builder
	flush := func() {
		if current == "" {
			return
		}
		value := strings.TrimSpace(builder.String())
		if _, exists := out[current]; !exists {
			out[current] = value
		}
		current = ""
		builder.Reset()
	}
	for _, line := range lines {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") && current != "" {
			builder.WriteString(strings.TrimPrefix(line, " "))
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		current = strings.ToLower(strings.TrimSpace(line[:idx]))
		builder.WriteString(strings.TrimSpace(line[idx+1:]))
	}
	flush()
	return out
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
