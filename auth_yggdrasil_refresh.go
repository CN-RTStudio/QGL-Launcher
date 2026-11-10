package main

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) RefreshExternalToken(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	authData, err := a.GetExternalAuthData(username)
	if err != nil {
		return fmt.Errorf("获取外置认证数据失败: %v", err)
	}
	refreshURL := authData.ServerURL + "/authserver/refresh"
	payload := map[string]interface{}{
		"accessToken": authData.AccessToken,
		"clientToken": authData.ClientToken,
		"requestUser": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("构建请求失败: %v", err)
	}
	req, err := http.NewRequest("POST", refreshURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := yggHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}
	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if authResp.Error != "" {
		if authData.Password != "" {
			newAuthData, loginErr := a.LoginYggdrasil(authData.ServerURL, authData.Username, authData.Password)
			if loginErr != nil {
				return fmt.Errorf("令牌刷新失败且重新登录失败: %v", loginErr)
			}
			newAuthData.ServerURL = authData.ServerURL
			newAuthData.ServerName = authData.ServerName
			return a.SaveExternalAuthData(username, newAuthData)
		}
		return fmt.Errorf("令牌刷新失败: %s", authResp.ErrorMessage)
	}
	if why := validateYggToken(authResp.AccessToken, false); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-token", "RefreshExternalToken", why)
		return fmt.Errorf("%s", describeYggReject(why))
	}
	authData.AccessToken = authResp.AccessToken
	if why := validateYggToken(authResp.ClientToken, true); why == ypOK && authResp.ClientToken != "" {
		authData.ClientToken = authResp.ClientToken
	}
	// 刷新响应若带角色资料，同样必须通过名校验与 UUID 归一；非法则保留旧身份不覆盖。
	if profile, ok := pickYggProfile(authResp.SelectedProfile, authResp.AvailableProfiles); ok {
		authData.UUID = profile.UUID
		authData.Username = profile.Name
	} else if authResp.SelectedProfile != nil {
		recordSecurityEvent("auth", "medium", "ignore-ygg-profile", "RefreshExternalToken", "invalid refreshed profile")
	}
	return a.SaveExternalAuthData(username, authData)
}

// DownloadAuthlibInjector 下载并强校验 authlib-injector.jar（javaagent，可执行）。
// 已存在的 jar 也必须通过侧车记录的官方 SHA-256 复核，绝不"文件在就直接用"。
func (a *App) DownloadAuthlibInjector() (string, error) {
	qglDir := a.GetQGLDir()
	jarPath := filepath.Join(qglDir, "authlib-injector.jar")
	if err := os.MkdirAll(qglDir, 0700); err != nil {
		return "", fmt.Errorf("创建目录失败: %v", err)
	}

	downloadURL, expectedSHA256, err := fetchAuthlibLatest()
	if err != nil {
		// 拿不到权威哈希时，只有"已有 jar 且侧车自证完整"才可继续离线复用；
		// 但侧车里的期望值同样来自上次官方哈希，此处无新值，保守起见要求网络可用。
		return "", err
	}

	if state := inspectRegularFile(jarPath); state.trustable() {
		if verifyAuthlibJar(jarPath, expectedSHA256) {
			return jarPath, nil
		}
		// 已存在但哈希不符 / 无侧车：可能被篡改或是旧版本，删除后重下。
		os.Remove(jarPath)
		removeAuthlibMeta(jarPath)
	}

	mirrorURL := strings.ReplaceAll(downloadURL,
		"authlib-injector.yushi.moe",
		"bmclapi2.bangbang93.com/mirrors/authlib-injector")
	candidates := []string{downloadURL}
	if isAllowedAuthlibDownloadURL(mirrorURL) && mirrorURL != downloadURL {
		candidates = append(candidates, mirrorURL)
	}
	if err := downloadAuthlibJarFromCandidates(jarPath, candidates, expectedSHA256); err != nil {
		return "", err
	}
	return jarPath, nil
}

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

func downloadAuthlibJarFromCandidates(jarPath string, candidates []string, expectedSHA256 string) error {
	if len(expectedSHA256) == 0 {
		return fmt.Errorf("缺少 authlib-injector 官方 SHA-256，拒绝下载")
	}
	var lastErr error
	for _, u := range candidates {
		if !isAllowedAuthlibDownloadURL(u) {
			lastErr = fmt.Errorf("下载地址不在可信主机白名单: %s", u)
			continue
		}
		if err := func() error {
			resp, err := httpClient.Get(u)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			// 用 O_EXCL 写同目录临时文件，绝不直接 O_TRUNC 覆盖正在被使用的 jar。
			dir := filepath.Dir(jarPath)
			tmp, err := os.CreateTemp(dir, ".authlib-*.jar.tmp")
			if err != nil {
				return fmt.Errorf("创建临时文件失败: %w", err)
			}
			tmpName := tmp.Name()
			abort := func(cause error) error {
				tmp.Close()
				os.Remove(tmpName)
				return cause
			}
			// 多读 1 字节用于判定是否超限。
			n, err := io.CopyN(tmp, resp.Body, authlibJarMaxBytes+1)
			if err != nil && err != io.EOF {
				return abort(fmt.Errorf("写入文件失败: %w", err))
			}
			if n > authlibJarMaxBytes {
				return abort(fmt.Errorf("authlib-injector 体积超过 %d 字节上限", authlibJarMaxBytes))
			}
			if err := tmp.Close(); err != nil {
				os.Remove(tmpName)
				return fmt.Errorf("关闭临时文件失败: %w", err)
			}

			got, herr := sha256FileHex(tmpName)
			if herr != nil {
				os.Remove(tmpName)
				return fmt.Errorf("计算哈希失败: %w", herr)
			}
			if !hmac.Equal([]byte(got), []byte(expectedSHA256)) {
				os.Remove(tmpName)
				return fmt.Errorf("文件哈希校验失败: 预期 %s, 实际 %s", expectedSHA256, got)
			}
			if err := os.Rename(tmpName, jarPath); err != nil {
				os.Remove(tmpName)
				return fmt.Errorf("替换 jar 失败: %w", err)
			}
			info, _ := os.Stat(jarPath)
			var size int64
			if info != nil {
				size = info.Size()
			}
			if err := saveAuthlibMeta(jarPath, expectedSHA256, size); err != nil {
				// jar 本体已可信，侧车写失败不应致命，下次启动会重新校验/下载。
				removeAuthlibMeta(jarPath)
			}
			return nil
		}(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("下载 authlib-injector 失败: %v", lastErr)
}

const authlibJarMaxBytes = 64 << 20

var authlibDownloadHosts = map[string]bool{
	"authlib-injector.yushi.moe": true,
	"bmclapi2.bangbang93.com":    true,
}

func isAllowedAuthlibDownloadURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	return authlibDownloadHosts[strings.ToLower(u.Hostname())]
}
