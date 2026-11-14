package main

import (
	"strings"
)

const (
	pjReasonOK           = "ok"
	pjReasonMissing      = "missing"
	pjReasonEmpty        = "empty-plugins-dir"
	pjReasonUnreadable   = "unreadable"
	pjReasonTooLarge     = "too-large"
	pjReasonTooMany      = "too-many"
	pjReasonSymlink      = "symlink"
	pjReasonBadName      = "bad-name"
	pjReasonNoDescriptor = "missing-plugin-yml"
	pjReasonNoMain       = "missing-main-class"
	pjReasonBadMain      = "bad-main-class"
	pjReasonNestedJar    = "nested-jar"
	pjReasonExecBit      = "executable-bit"
	pjReasonShellClass   = "shell-capable-main"
	pjReasonUnsigned     = "unsigned"
	pjReasonWeakDigest   = "weak-digest"
	pjReasonDuplicateJar = "duplicate-jar"
	pjReasonTooManyFiles = "too-many-entries"

	pjMaxJarBytes    = 64 << 20
	pjMaxJars        = 128
	pjMaxEntries     = 4096
	pjMaxFindings    = 160
	pjMaxMainLen     = 200
	pjMaxNestedDepth = 2
)

var pjSelectedPaths = []string{
	"META-INF/MANIFEST.MF",
	"META-INF/",
	"plugin.yml",
	"paper-plugin.yml",
	"bungee.yml",
	"velocity-plugin.json",
}

var pjShellyMainTokens = []string{
	"runtime.exec",
	"processbuilder",
	"scriptengine",
	"shell",
	"cmd",
	"exec",
}

func pjDescriptorName(entries map[string]bool) string {
	for _, name := range []string{"plugin.yml", "paper-plugin.yml", "bungee.yml", "velocity-plugin.json"} {
		if entries[name] {
			return name
		}
	}
	return ""
}
func pjMainClass(descriptor, body string) (string, bool) {
	if strings.HasSuffix(descriptor, ".json") {
		const key = "\"main\""
		idx := strings.Index(body, key)
		if idx < 0 {
			return "", false
		}
		rest := body[idx+len(key):]
		colon := strings.Index(rest, ":")
		if colon < 0 {
			return "", false
		}
		rest = rest[colon+1:]
		quote := strings.Index(rest, "\"")
		if quote < 0 {
			return "", false
		}
		rest = rest[quote+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			return "", false
		}
		return strings.TrimSpace(rest[:end]), true
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "main:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "main:"))
		value = strings.Trim(value, "'\"")
		return value, true
	}
	return "", false
}
