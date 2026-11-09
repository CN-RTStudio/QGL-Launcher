package main

import (
	"path/filepath"
	"strings"
)

const maxDownloadSavePathLen = 1024

const (
	dfRejectNone          = ""
	dfRejectSavePath      = "bad-save-path"
	dfRejectJavaMajor     = "java-major-range"
	dfRejectLoaderName    = "loader-name-unknown"
	dfRejectLoaderVersion = "loader-version-missing"
	dfRejectOptiFine      = "optifine-args-missing"
	dfRejectModExt        = "mod-extension"
)

var allowedLoaderNames = map[string]bool{
	"forge":    true,
	"fabric":   true,
	"neoforge": true,
	"optifine": true,
}

var allowedModExtensions = map[string]bool{
	".jar":      true,
	".zip":      true,
	".disabled": true,
}

func auditDownloadSavePath(item DownloadItem, mcDir string) string {
	if item.SavePath == "" {
		return dfRejectNone
	}
	if len(item.SavePath) > maxDownloadSavePathLen {
		return dfRejectSavePath
	}
	if containsControlChar(item.SavePath) {
		return dfRejectSavePath
	}
	if strings.TrimSpace(item.SavePath) == "" {
		return dfRejectSavePath
	}
	if !filepath.IsAbs(item.SavePath) {
		return dfRejectSavePath
	}
	clean := filepath.Clean(item.SavePath)
	if clean != item.SavePath {
		return dfRejectSavePath
	}
	if mcDir == "" {
		return dfRejectSavePath
	}
	if _, ok := PathWithin(mcDir, clean); !ok {
		return dfRejectSavePath
	}
	return dfRejectNone
}
