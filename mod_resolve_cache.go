package main

import (
	"path/filepath"
	"strings"
)

func (a *App) GetDefaultModDir(versionID string) string {
	mcDir := a.GetMinecraftDir()
	if versionID != "" && !strings.Contains(versionID, "..") && !strings.Contains(versionID, "/") && !strings.Contains(versionID, "\\") {
		return filepath.Join(mcDir, "versions", versionID, "mods")
	}
	return filepath.Join(mcDir, "mods")
}
