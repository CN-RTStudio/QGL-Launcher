package main

import (
	"os"
	"path/filepath"

)

func copyDirContents(srcDir string, dstDir string) error {
	os.MkdirAll(dstDir, 0755)

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		data, err := os.ReadFile(srcPath)
		if err != nil {
			continue
		}
		os.WriteFile(dstPath, data, 0644)
	}

	return nil
}

// generateOfflineUUID 根据用户名生成离线 UUID
