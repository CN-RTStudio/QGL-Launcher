package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GetAuthlibInjectorPath 获取 authlib-injector.jar 路径（不存在则下载）
func (a *App) GetAuthlibInjectorPath() (string, error) {
	return a.DownloadAuthlibInjector()
}

func fetchAuthlibLatest() (downloadURL, expectedSHA256 string, err error) {
	latestURLs := []string{
		"https://authlib-injector.yushi.moe/artifact/latest.json",
		"https://bmclapi2.bangbang93.com/mirrors/authlib-injector/artifact/latest.json",
	}
	for _, u := range latestURLs {
		resp, gerr := httpClient.Get(u)
		if gerr != nil {
			continue
		}
		body, _ := readAuthJSON(resp)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var info map[string]string
		if jerr := json.Unmarshal(body, &info); jerr != nil {
			continue
		}
		du := strings.TrimSpace(info["download_url"])
		sha := strings.ToLower(strings.TrimSpace(info["sha256"]))
		if du != "" && sha != "" && isAllowedAuthlibDownloadURL(du) {
			return du, sha, nil
		}
	}
	return "", "", fmt.Errorf("获取可信的 authlib-injector 下载地址/哈希失败")
}
