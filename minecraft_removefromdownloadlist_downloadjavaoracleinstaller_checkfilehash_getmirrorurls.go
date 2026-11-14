package main

import (
	"strings"

)

func (a *App) getMirrorURLs(originalURL string) []string {
	var urls []string

	// Forge Maven
	if strings.Contains(originalURL, "maven.minecraftforge.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// NeoForge Maven
	if strings.Contains(originalURL, "maven.neoforged.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.neoforged.net/releases/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Fabric Maven
	if strings.Contains(originalURL, "maven.fabricmc.net") {
		mirrorURL := strings.Replace(originalURL, "https://maven.fabricmc.net/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Minecraft 官方库
	if strings.Contains(originalURL, "libraries.minecraft.net") {
		mirrorURL := strings.Replace(originalURL, "https://libraries.minecraft.net/", "https://bmclapi2.bangbang93.com/libraries/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Maven Central
	if strings.Contains(originalURL, "repo1.maven.org") {
		mirrorURL := strings.Replace(originalURL, "https://repo1.maven.org/maven2/", "https://bmclapi2.bangbang93.com/maven/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// Mojang 资源
	if strings.Contains(originalURL, "launcher.mojang.com") || strings.Contains(originalURL, "piston-data.mojang.com") || strings.Contains(originalURL, "piston-meta.mojang.com") {
		mirrorURL := strings.Replace(originalURL, "https://launcher.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		mirrorURL = strings.Replace(mirrorURL, "https://piston-data.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		mirrorURL = strings.Replace(mirrorURL, "https://piston-meta.mojang.com/v1/objects/", "https://bmclapi2.bangbang93.com/version/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// 资源文件
	if strings.Contains(originalURL, "resources.download.minecraft.net") {
		mirrorURL := strings.Replace(originalURL, "https://resources.download.minecraft.net/", "https://bmclapi2.bangbang93.com/assets/", 1)
		urls = append(urls, mirrorURL, originalURL)
		return urls
	}

	// 默认：原 URL
	urls = append(urls, originalURL)
	return urls
}

// downloadFromMirrors 从多个镜像源尝试下载（参考 PCL 的多源下载策略）
