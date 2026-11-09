package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// GetVersionManifest 获取版本清单
func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}
	var manifest VersionManifest
	opts := jsonFetchOptions{
		MaxBytes:        maxVersionManifestBytes,
		Attempts:        2,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:          safeHTTPClient(),
		AllowMediaTypes: []string{"application/json"},
		SourceLabel:     "版本清单",
	}
	if err := fetchJSONFromMirrors(context.Background(), urls, &manifest, opts); err != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", err)
	}
	var result []MCVersion
	for _, v := range manifest.Versions {
		if v.Type == "release" || v.Type == "snapshot" {
			result = append(result, MCVersion{ID: v.ID, Type: v.Type, URL: v.URL, ReleaseTime: v.ReleaseTime})
		}
	}
	return result, nil
}

func (a *App) GetInstalledVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}
	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}
		info := a.readVersionInfo(versionFolder, entry.Name())
		installed = append(installed, info)
	}
	return installed, nil
}

func (a *App) ScanVersions() ([]InstalledVersionInfo, error) {
	mcDir := a.getMinecraftDir()
	versionsDir := filepath.Join(mcDir, "versions")
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstalledVersionInfo{}, nil
		}
		return nil, fmt.Errorf("读取版本目录失败: %v", err)
	}
	var installed []InstalledVersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		versionFolder := filepath.Join(versionsDir, entry.Name())
		if !a.validateVersionInstallation(versionFolder) {
			continue
		}
		info := a.scanVersionFolder(versionFolder, entry.Name())
		installed = append(installed, info)
	}
	return installed, nil
}
