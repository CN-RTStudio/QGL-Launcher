package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func fetchNeoForgeVersionList(apiURL string) ([]string, error) {
	if !isHTTPSURL(apiURL) {
		return nil, fmt.Errorf("不安全的 URL 协议")
	}

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := readLimited(resp.Body, apiJSONMaxBytes)
	if err != nil {
		return nil, err
	}

	var data struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &data); err == nil && len(data.Versions) > 0 {
		return data.Versions, nil
	}

	var mavenData struct {
		Versions struct {
			Version []string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &mavenData); err == nil && len(mavenData.Versions.Version) > 0 {
		return mavenData.Versions.Version, nil
	}

	return nil, fmt.Errorf("无法解析版本列表")
}
