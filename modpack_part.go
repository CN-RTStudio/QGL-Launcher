package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

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

// SearchModpacks 搜索 Modrinth 整合包
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
