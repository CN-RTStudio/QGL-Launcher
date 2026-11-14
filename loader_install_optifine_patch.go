package main

import (
	"os"
	"path/filepath"
)

func (a *App) validateVersionInstallation(versionFolder string) bool {
	info, err := os.Lstat(versionFolder)
	if err != nil || !info.IsDir() {
		return false
	}

	jsonFiles, err := filepath.Glob(filepath.Join(versionFolder, "*.json"))
	if err != nil || len(jsonFiles) == 0 {
		return false
	}

	for _, jsonFile := range jsonFiles {
		var jsonData map[string]interface{}
		if err := readLocalJSONBounded(jsonFile, &jsonData, 0, "版本 JSON"); err != nil {
			continue
		}

		if jsonData["id"] == nil || jsonData["mainClass"] == nil {
			continue
		}

		return true
	}

	return false
}
