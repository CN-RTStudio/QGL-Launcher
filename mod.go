package main

import (
	"strings"

)

// ===== Modrinth API 相关结构体 =====

// ModSearchResult Mod 搜索结果
type ModSearchResult struct {
	ProjectID    string   `json:"project_id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"versions"`  // Modrinth API 字段名为 "versions"
	Loaders      []string `json:"loaders"`
}

// ModSearchResponse Mod 搜索响应
type ModSearchResponse struct {
	Hits      []ModSearchResult `json:"hits"`
	TotalHits int               `json:"total_hits"`
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
}

// ModVersion Mod 版本信息
type ModVersion struct {
	ID            string          `json:"id"`
	ProjectID     string          `json:"project_id"`
	Name          string          `json:"name"`
	VersionNumber string          `json:"version_number"`
	GameVersions  []string        `json:"game_versions"`
	Loaders       []string        `json:"loaders"`
	Files         []ModFile       `json:"files"`
	Dependencies  []ModDependency `json:"dependencies"`
	Changelog     string          `json:"changelog"`
}

// ModFile Mod 文件信息
type ModFile struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	Primary  bool   `json:"primary"`
	SHA1     string `json:"sha1"`
}

// ModDependency Mod 依赖
type ModDependency struct {
	ProjectID      string `json:"project_id"`
	VersionID      string `json:"version_id"`
	DependencyType string `json:"dependency_type"`
}

// ModDetail Mod 详情
type ModDetail struct {
	ID           string   `json:"id"`
	Slug         string   `json:"slug"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Body         string   `json:"body"`
	IconURL      string   `json:"icon_url"`
	Downloads    int      `json:"downloads"`
	ClientSide   string   `json:"client_side"`
	ServerSide   string   `json:"server_side"`
	Categories   []string `json:"categories"`
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
	ProjectType  string   `json:"project_type"`
}

// ModDependencyInfo 前端显示用的依赖信息
type ModDependencyInfo struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	DependencyType string `json:"dependencyType"`
}

// ModCategory Mod 分类
type ModCategory struct {
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	ProjectType string `json:"project_type"`
}

// ModFileInfo Mod 文件信息（管理用）
type ModFileInfo struct {
	FileName  string `json:"fileName"`
	FilePath  string `json:"filePath"`
	IsEnabled bool   `json:"isEnabled"`
	FileSize  int64  `json:"fileSize"`
}

const modrinthBaseURL = "https://api.modrinth.com/v2"

// mirrorModURL 将 Mod 下载 URL 替换为中国镜像源（参考 PCL 的 DlSourceModGet）
// Modrinth CDN -> mod.mcimirror.top/modrinth
// CurseForge -> mod.mcimirror.top/curseforge
func mirrorModURL(original string) string {
	u := original
	u = strings.Replace(u, "https://cdn.modrinth.com", "https://mod.mcimirror.top/modrinth", 1)
	u = strings.Replace(u, "https://api.modrinth.com", "https://mod.mcimirror.top/modrinth", 1)
	u = strings.Replace(u, "https://edge.forgecdn.net", "https://mod.mcimirror.top/curseforge", 1)
	u = strings.Replace(u, "https://mediafilez.forgecdn.net", "https://mod.mcimirror.top/curseforge", 1)
	return u
}

// SearchMods 搜索 Mod
