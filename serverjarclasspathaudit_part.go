package main

import (
	"strings"
	"unicode"
)

func (a *JarClassPathAudit) add(jar, entry, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jarCpMaxFindingsPerJar*jarCpMaxJars, JarCPFinding{Jar: jar, Entry: entry, Reason: reason, Detail: detail, Blocking: blocking})
}
func jarCPUnfoldManifest(data []byte) []string {
	raw := strings.ReplaceAll(string(data), "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, " ") && len(lines) > 0 {
			lines[len(lines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
func jarCPEntries(value string) []string {
	out := []string{}
	for _, part := range strings.Fields(value) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
func jarCPDriveLetter(entry string) bool {
	if len(entry) < 2 || entry[1] != ':' {
		return false
	}
	c := entry[0]
	return unicode.IsLetter(rune(c)) && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
}
func jarCPIsAbsolute(entry string) bool {
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\\`) {
		return true
	}
	return jarCPDriveLetter(entry)
}
func jarCPIsRemote(entry string) bool {
	lower := strings.ToLower(entry)
	for _, scheme := range []string{"http://", "https://", "ftp://", "jar:", "file:"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}
