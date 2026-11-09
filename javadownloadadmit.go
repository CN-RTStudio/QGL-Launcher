package main

import (
	"path/filepath"
	"strings"
)

const maxJavaArtifactNameLen = 120

const (
	jdRejectNone           = ""
	jdRejectUnknownMajor   = "java-unknown-major"
	jdRejectBadName        = "java-bad-filename"
	jdRejectBadCatalogURL  = "java-bad-catalog-url"
	jdRejectURLMismatch    = "java-url-mismatch"
	jdRejectUnsafeArtifact = "java-unsafe-artifact"
)

var javaArtifactExtensions = map[string]bool{
	".zip": true,
	".msi": true,
	".exe": true,
	".pkg": true,
	".dmg": true,
}

func findJavaDownloadInfo(list []JavaDownloadInfo, major int) (JavaDownloadInfo, bool) {
	for i := range list {
		if list[i].MajorVer == major {
			return list[i], true
		}
	}
	return JavaDownloadInfo{}, false
}

func auditJavaArtifactName(name string) string {
	if strings.TrimSpace(name) == "" {
		return jdRejectBadName
	}
	if len(name) > maxJavaArtifactNameLen {
		return jdRejectBadName
	}
	if containsControlChar(name) {
		return jdRejectBadName
	}
	if strings.ContainsAny(name, `/\:*?"<>|`) {
		return jdRejectBadName
	}
	if name == "." || name == ".." || strings.HasPrefix(name, "..") {
		return jdRejectBadName
	}
	if !javaArtifactExtensions[strings.ToLower(filepath.Ext(name))] {
		return jdRejectUnsafeArtifact
	}
	return jdRejectNone
}
