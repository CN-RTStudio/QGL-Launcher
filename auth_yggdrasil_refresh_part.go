package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const authlibJarMaxBytes = 64 << 20

// authlibDownloadHosts 是允许下载 authlib jar 的主机白名单。
// latest.json 里的 download_url 来自远程，绝不能无条件跟随：
// 被劫持的元数据可能把它指向任意主机的木马 jar。
var authlibDownloadHosts = map[string]bool{
	"authlib-injector.yushi.moe": true,
	"bmclapi2.bangbang93.com":    true,
}

// isAllowedAuthlibDownloadURL 只放行 https、无 userinfo、主机在白名单内的地址。
func isAllowedAuthlibDownloadURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	return authlibDownloadHosts[strings.ToLower(u.Hostname())]
}

// fetchAuthlibLatest 从两个官方/镜像元数据端点获取下载地址与权威 SHA-256。
// 两个字段缺一不可：没有哈希就无法保证下载到的 javaagent 没被掉包。
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
