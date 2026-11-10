package main

import (
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// 解压覆写文件时的大小上限，防止 zip bomb（高压缩比小文件膨胀占满磁盘）。
const (
	maxOverridesEntryBytes int64 = 8 << 30   // 单个文件最多 8 GiB（正常整合包条目远小于此，只有解压炸弹才会触发）
	maxOverridesTotalBytes int64 = 256 << 30 // 全部覆写文件合计最多 256 GiB（只在明显炸磁盘时中止）
	maxMrpackDownloadBytes int64 = 8 << 30   // 整合包本体最多 8 GiB，与单文件上限一致
	maxMrpackManifestBytes int64 = 16 << 20  // modrinth.index.json 最多 16 MiB（清单只是文件列表，正常远小于此）
	maxOverridesEntries          = 100000    // 覆写条目数上限，防海量空文件耗尽 inode / 拖慢解压
)

// unsafeEntryMode 拒绝在覆写区落地的特殊文件类型：符号链接 / 设备 / 管道 / 套接字。
// zip 里这类条目本不该出现在整合包，放行符号链接还可能被利用做链接逃逸或诱导覆盖。
const unsafeEntryMode = os.ModeSymlink | os.ModeDevice | os.ModeNamedPipe | os.ModeSocket

// ===== Modrinth 整合包 API 结构体 =====

type ModpackSearchResult = ModSearchResult
type ModpackSearchResponse = ModSearchResponse

type ModrinthModpackManifest struct {
	FormatVersion int                   `json:"formatVersion"`
	Game          string                `json:"game"`
	VersionID     string                `json:"versionId"`
	Name          string                `json:"name"`
	Files         []ModrinthModpackFile `json:"files"`
	Dependencies  map[string]string     `json:"dependencies"`
}

type ModrinthModpackFile struct {
	Path      string            `json:"path"`
	Hashes    map[string]string `json:"hashes"`
	Downloads []string          `json:"downloads"`
	FileSize  int64             `json:"fileSize"`
	// Env 是 Modrinth 规范的端侧声明 {"client","server"} = required|optional|unsupported。
	// 客户端安装时只选取 client != unsupported 的文件；缺失视为两侧都需要。
	Env map[string]string `json:"env"`
}

// sha1File 计算文件 SHA1（仅作 sha512 缺失时的回退）
func sha1File(path string) (string, error) {
	return hashFileHex(crypto.SHA1, path)
}

// ===== UMFS 本地完整性缓存 =====
// 首次下载用 Modrinth 给的 sha512 验完后，把文件的 UMFS-256 指纹缓存到本地；
// 以后再遇到同一文件（用 Modrinth 的 sha512/sha1 当 key）就优先比对 UMFS。
// 优先级：缓存 UMFS → manifest sha512 → manifest sha1。

func verifyDownloadedFile(path string, hashes map[string]string, cache *umfsCache) error {
	want512 := strings.ToLower(strings.TrimSpace(hashes["sha512"]))
	want1 := strings.ToLower(strings.TrimSpace(hashes["sha1"]))

	pinUMFS := func() {
		if cache == nil {
			return
		}
		key := cache.keyFor(hashes)
		if key == "" {
			return
		}
		if u, err := umfsFile(path); err == nil {
			cache.set(key, u)
		}
	}

	// 1) 缓存命中：优先 UMFS
	if cache != nil {
		if key := cache.keyFor(hashes); key != "" {
			if want, ok := cache.get(key); ok {
				got, err := umfsFile(path)
				if err != nil {
					return err
				}
				if got == want {
					return nil
				}
				// UMFS 不匹配：可能是文件被换过，继续走下面的官方摘要校验
				os.Remove(path)
				return fmt.Errorf("UMFS 缓存校验失败 (期望 %s, 实际 %s)", want, got)
			}
		}
	}

	// 2) sha512
	if want512 != "" {
		got, err := sha512File(path)
		if err != nil {
			return err
		}
		if got != want512 {
			os.Remove(path)
			return fmt.Errorf("SHA-512 校验失败 (期望 %s, 实际 %s)", want512, got)
		}
		pinUMFS()
		return nil
	}

	// 3) sha1 回退
	if want1 != "" {
		got, err := sha1File(path)
		if err != nil {
			return err
		}
		if got != want1 {
			os.Remove(path)
			return fmt.Errorf("SHA-1 校验失败 (期望 %s, 实际 %s)", want1, got)
		}
		pinUMFS()
		return nil
	}

	return nil
}

func (a *App) SearchModpacks(query string, gameVersion string, page int, pageSize int) (*ModpackSearchResponse, error) {
	// r35：与 SearchMods 对齐——分页 / 查询入参全部来自前端，必须收敛，防止被塞入
	// 超大 limit 打出超长 Modrinth URL 或巨大 offset；Modrinth 单页上限 100，此处兜底。
	const (
		defaultModpackPageSize = 20
		maxModpackPageSize     = 100
		maxModpackQueryLen     = 200
	)
	if pageSize <= 0 {
		pageSize = defaultModpackPageSize
	}
	if pageSize > maxModpackPageSize {
		pageSize = maxModpackPageSize
	}
	if page < 0 {
		page = 0
	}
	if len(query) > maxModpackQueryLen {
		query = query[:maxModpackQueryLen]
	}
	query = strings.TrimSpace(query)
	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", page*pageSize))
	params.Set("index", "relevance")

	var facets []string
	facets = append(facets, `["project_type:modpack"]`)
	if gameVersion != "" && isValidMCVersion(gameVersion) {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}

	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("搜索整合包失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp, "搜索整合包失败")
	}

	var result ModpackSearchResponse
	if err := readAPIJSON(resp, &result); err != nil {
		return nil, fmt.Errorf("解析搜索结果失败: %v", err)
	}

	if result.Hits == nil {
		result.Hits = []ModpackSearchResult{}
	}
	for i := range result.Hits {
		if result.Hits[i].Categories == nil {
			result.Hits[i].Categories = []string{}
		}
		if result.Hits[i].GameVersions == nil {
			result.Hits[i].GameVersions = []string{}
		}
		if result.Hits[i].Loaders == nil {
			result.Hits[i].Loaders = []string{}
		}
	}

	return &result, nil
}

// GetModpackVersions 获取整合包版本列表
func (a *App) GetModpackVersions(projectID string) ([]ModVersion, error) {
	if !isValidModID(projectID) {
		return nil, fmt.Errorf("无效的项目 ID 格式")
	}
	apiURL := fmt.Sprintf("%s/project/%s/version", modrinthBaseURL, projectID)
	resp, err := safeHTTPClient().Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取整合包版本失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取整合包版本失败: HTTP %d", resp.StatusCode)
	}

	var versions []ModVersion
	if err := readAPIJSON(resp, &versions); err != nil {
		return nil, fmt.Errorf("解析版本列表失败: %v", err)
	}

	if versions == nil {
		versions = []ModVersion{}
	}
	return versions, nil
}

// AddModpackToDownloadList 添加整合包到下载列表
