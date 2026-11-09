package main

// 目录包含判定统一使用 sanitize.PathWithin：它除了词法边界检查，还做真实符号链接
// 解析（isPathInDir 旧实现只看 filepath.Rel，root 内被预置指向外部的链接时会漏判）。

// isValidModID 验证 Mod ID 格式，防止 URL 注入
func isValidModID(id string) bool {
	if len(id) > 100 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ===== Modrinth API 相关结构体 =====

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
	GameVersions []string `json:"game_versions"`
	Loaders      []string `json:"loaders"`
}

type ModSearchResponse struct {
	Hits      []ModSearchResult `json:"hits"`
	TotalHits int               `json:"total_hits"`
	Offset    int               `json:"offset"`
	Limit     int               `json:"limit"`
}

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

type ModFile struct {
	Filename string            `json:"filename"`
	URL      string            `json:"url"`
	Size     int64             `json:"size"`
	Primary  bool              `json:"primary"`
	SHA1     string            `json:"sha1"`
	Hashes   map[string]string `json:"hashes"`
}

type ModDependency struct {
	ProjectID      string `json:"project_id"`
	VersionID      string `json:"version_id"`
	DependencyType string `json:"dependency_type"`
}

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

type ModDependencyInfo struct {
	ProjectID      string `json:"projectId"`
	ProjectName    string `json:"projectName"`
	IconURL        string `json:"iconUrl"`
	DependencyType string `json:"dependencyType"`
}

type ModCategory struct {
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	ProjectType string `json:"project_type"`
}

type ModFileInfo struct {
	FileName  string `json:"fileName"`
	FilePath  string `json:"filePath"`
	IsEnabled bool   `json:"isEnabled"`
	FileSize  int64  `json:"fileSize"`
}

const modrinthBaseURL = "https://api.modrinth.com/v2"

// 下载期望值（哈希/大小）的并发安全存储、完整性校验、下载主机白名单与
// 符号链接安全落盘都已收口到 modverify.go（var modExpect 等）。
