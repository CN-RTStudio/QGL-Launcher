package main

import (
	_ "embed"
	"os"
	"path/filepath"

)

func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

// runForgeInstaller 运行 bangbang93 ForgeInstaller（完全按照 PCL 的命令行）
