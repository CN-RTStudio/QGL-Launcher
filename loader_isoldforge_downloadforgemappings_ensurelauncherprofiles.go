package main

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) ensureLauncherProfiles(mcDir string) {
	profilesPath := filepath.Join(mcDir, "launcher_profiles.json")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		profiles := map[string]interface{}{
			"profiles": map[string]interface{}{},
		}
		data, _ := json.MarshalIndent(profiles, "", "  ")
		os.WriteFile(profilesPath, data, 0644)
	}
}

// getVersionFolderList 获取当前版本文件夹列表
