package main

import (
	"archive/zip"
	_ "embed"
	"io"
	"os"
	"path/filepath"
	"strings"

)

func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")

	for _, f := range r.File {
		// 只解压 maven/ 目录下的文件
		if strings.HasPrefix(f.Name, "maven/") && !f.FileInfo().IsDir() {
			relPath := strings.TrimPrefix(f.Name, "maven/")
			destPath, ok := archiveEntryPathInside(libsDir, relPath)
			if !ok {
				a.recordSecurityEventBlockedArchive("extractMavenFiles", libsDir, f.Name)
				continue
			}

			os.MkdirAll(filepath.Dir(destPath), 0755)

			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			os.WriteFile(destPath, data, 0644)
		}
	}

	return nil
}

// downloadForgeLibraries 分析并下载 Forge 支持库文件
