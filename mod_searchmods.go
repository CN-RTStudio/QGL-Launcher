package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

)

func (a *App) SearchMods(query string, gameVersion string, loader string, category string, page int, pageSize int) (*ModSearchResponse, error) {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page < 0 {
		page = 0
	}

	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", page*pageSize))
	params.Set("index", "relevance")

	var facets []string
	facets = append(facets, `["project_type:mod"]`)

	if gameVersion != "" {
		facets = append(facets, fmt.Sprintf(`["versions:%s"]`, gameVersion))
	}
	if loader != "" {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, loader))
	}
	if category != "" {
		facets = append(facets, fmt.Sprintf(`["categories:%s"]`, category))
	}

	if len(facets) > 0 {
		facetsJSON := fmt.Sprintf("[%s]", strings.Join(facets, ","))
		params.Set("facets", facetsJSON)
	}

	apiURL := fmt.Sprintf("%s/search?%s", modrinthBaseURL, params.Encode())

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("搜索 Mod 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("搜索 Mod 失败: HTTP %d, %s", resp.StatusCode, string(body))
	}

	var result ModSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析搜索结果失败: %v", err)
	}

	// 确保返回非 nil slice
	if result.Hits == nil {
		result.Hits = []ModSearchResult{}
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

// GetModDetail 获取 Mod 详情
