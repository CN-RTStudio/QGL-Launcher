package main

import (
	"os"
	"strings"
)

// checkFileHash 校验文件完整性（SHA1，用于验证 Mojang manifest 提供的哈希）
func (a *App) checkFileHash(filePath string, expectedSHA1 string) bool {
	info, err := os.Stat(filePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA1))
	if expected == "" {
		return true
	}
	return fileSHA1Matches(filePath, expected)
}

func (a *App) getMirrorURLs(originalURL string) []string {
	var urls []string
	addMirror := func(mirror, original string) {
		urls = append(urls, mirror, original)
	}
	switch {
	case strings.Contains(originalURL, "maven.minecraftforge.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "maven.neoforged.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "maven.fabricmc.net"):
		addMirror(rewriteMavenLibURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "libraries.minecraft.net"):
		addMirror(rewriteLibraryArtifactURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "repo1.maven.org"):
		addMirror(rewriteMavenCentralURLToBMCL(originalURL), originalURL)
	case strings.Contains(originalURL, "launcher.mojang.com"), strings.Contains(originalURL, "piston-data.mojang.com"), strings.Contains(originalURL, "piston-meta.mojang.com"):
		m := rewriteObjectVersionURLToBMCL(originalURL)
		addMirror(m, originalURL)
	case strings.Contains(originalURL, "resources.download.minecraft.net"):
		addMirror(rewriteAssetURLToBMCL(originalURL), originalURL)
	default:
		urls = append(urls, originalURL)
	}
	return urls
}
