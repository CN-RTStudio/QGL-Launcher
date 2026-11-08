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

// ===== Yggdrasil 外置登录 =====

type YggdrasilAuthResponse struct {
	AccessToken       string `json:"accessToken"`
	ClientToken       string `json:"clientToken"`
	AvailableProfiles []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"availableProfiles"`
	SelectedProfile *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"selectedProfile"`
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
	Cause        string `json:"cause"`
}

type YggdrasilServerMeta struct {
	ServerName string `json:"serverName"`
}

type YggdrasilServerLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

type YggdrasilServerInfo struct {
	Meta  YggdrasilServerMeta  `json:"meta"`
	Links YggdrasilServerLinks `json:"links"`
}

// isLoopbackOrPrivateHost 判断 host 是否为回环/私网地址。
//
// 地址解析统一借 parseDestIP：除规范四段 / IPv6 外，还识别 127.1、2130706433、
// 0x7f000001、017700000001 等 inet_aton 短格式 / 进制混淆（历史上这里只调 net.ParseIP，
// 本地调试皮肤站写成 http://127.1 时会被误当公网而拒绝明文 HTTP）。允许范围刻意不变，
// 仍是回环 / RFC1918 私网 / 链路本地，不扩大到 CGNAT、0/8、多播等其它保留段。
func isLoopbackOrPrivateHost(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip, ok := parseDestIP(host); ok {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

// normalizeYggdrasilURL 规范化 Yggdrasil 服务器地址
//
// 安全要求：默认强制 HTTPS，因为 LoginYggdrasil 会明文 POST 用户密码。
// 仅当 host 是回环/私网（127.x / 10.x / 192.168.x / 172.16-31.x / ::1）时
// 才允许 http://，用于本地调试皮肤站。
//
// 历史 bug 修复：之前判断写成 `u.Scheme == "http://"`，而 url.Parse 给的 Scheme
// 永远是不带冒号斜杠的 "http"，导致该判断恒为 false——私网 http 调试也被错误拒绝。
// 现在按 u.Scheme == "http" 判断。
func normalizeYggdrasilURL(serverURL string) (string, error) {
	// 任何 ASCII 控制字符（含 CR/LF/Tab/NUL）都拒绝，且必须在 TrimSpace 之前检查：
	// 该地址随后会被拼进密码 POST 请求行，混入换行可能被截断、按后半段重解释。
	// 先剥空白再查会让用户输入里“尾随的换行 / 制表符”被静默吞掉——对认证地址这类
	// 高风险输入，选择显式拒绝而非悄悄归一化，便于前端提示用户修正。
	for i := 0; i < len(serverURL); i++ {
		if serverURL[i] < 0x20 || serverURL[i] == 0x7f {
			return "", fmt.Errorf("服务器地址含不可见控制字符，已拒绝")
		}
	}
	serverURL = strings.TrimSpace(serverURL)

	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		return "", fmt.Errorf("无效的服务器地址协议，只支持 http/https")
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("无法解析服务器地址: %v", err)
	}
	// 拒绝 userinfo 视觉混淆：https://trusted.example@evil.test/api/yggdrasil 用户看到
	// 的是 trusted，但密码实际发往 evil，必须在 POST 密码前拦下。
	if u.User != nil {
		return "", fmt.Errorf("服务器地址不允许携带用户名/密码(userinfo)，请去掉 @ 前的内容")
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("服务器地址缺少主机名")
	}
	if u.Scheme == "http" && !isLoopbackOrPrivateHost(u.Hostname()) {
		return "", fmt.Errorf("禁止通过明文 HTTP 连接公网 Yggdrasil 服务器（密码会被窃听），请使用 https://")
	}

	// 剥掉全部结尾斜杠（而不是只剥一个），避免 "…/api/yggdrasil//" 这类地址
	// 因单次 TrimSuffix 失配而被再次追加成 "…/api/yggdrasil//api/yggdrasil"。
	for strings.HasSuffix(serverURL, "/") {
		serverURL = strings.TrimSuffix(serverURL, "/")
	}
	if !strings.HasSuffix(serverURL, "/api/yggdrasil") {
		serverURL = serverURL + "/api/yggdrasil"
	}
	return serverURL, nil
}

// GetYggdrasilServerInfo 获取 Yggdrasil 服务器信息
func (a *App) GetYggdrasilServerInfo(serverURL string) (*YggdrasilServerInfo, error) {
	normalized, err := normalizeYggdrasilURL(serverURL)
	if err != nil {
		return nil, err
	}
	serverURL = normalized
	infoURL := strings.TrimSuffix(serverURL, "/api/yggdrasil")
	if !strings.HasSuffix(infoURL, "/") {
		infoURL += "/"
	}
	resp, err := yggHTTPClient.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("无法连接到验证服务器: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return nil, fmt.Errorf("读取服务器信息失败: %v", err)
	}
	var info YggdrasilServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("解析服务器信息失败: %v", err)
	}
	return &info, nil
}

// LoginYggdrasil Yggdrasil 外置登录
func (a *App) LoginYggdrasil(serverURL string, username string, password string) (*ExternalAuthData, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if !authRateLimiter.Allow("ygg-" + username) {
		return nil, fmt.Errorf("登录请求过于频繁，请稍后再试")
	}
	normalized, err := normalizeYggdrasilURL(serverURL)
	if err != nil {
		return nil, err
	}
	serverURL = normalized
	authURL := serverURL + "/authserver/authenticate"
	payload := map[string]interface{}{
		"agent": map[string]interface{}{
			"name":    "Minecraft",
			"version": 1,
		},
		"username":    username,
		"password":    password,
		"requestUser": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("构建请求失败: %v", err)
	}
	req, err := http.NewRequest("POST", authURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := yggHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接验证服务器失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	var authResp YggdrasilAuthResponse
	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}
	if authResp.Error != "" {
		errMsg := authResp.ErrorMessage
		if errMsg == "" {
			errMsg = authResp.Error
		}
		if authResp.Error == "ForbiddenOperationException" {
			return nil, fmt.Errorf("用户名或密码错误")
		}
		return nil, fmt.Errorf("登录失败: %s", errMsg)
	}
	if authResp.AccessToken == "" {
		return nil, fmt.Errorf("登录失败: 未获取到访问令牌")
	}
	// 令牌来自不可信外置服务器：限长且禁控制字符 / 空白（防存储膨胀与潜在头注入）。
	if why := validateYggToken(authResp.AccessToken, false); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-token", "LoginYggdrasil", why)
		return nil, fmt.Errorf("%s", describeYggReject(why))
	}
	if why := validateYggToken(authResp.ClientToken, true); why != ypOK {
		recordSecurityEvent("auth", "high", "reject-ygg-client-token", "LoginYggdrasil", why)
		authResp.ClientToken = ""
	}
	// 角色名 / UUID 会落盘成账号文件并进入启动命令行，必须按 Minecraft 字符集与
	// 32 位 hex 校验，拒绝恶意服务器返回的穿越名 / 注入名 / 畸形 UUID。
	profile, ok := pickYggProfile(authResp.SelectedProfile, authResp.AvailableProfiles)
	if !ok {
		recordSecurityEvent("auth", "high", "reject-ygg-profile", "LoginYggdrasil", "no valid profile")
		return nil, fmt.Errorf("外置服务器返回的角色资料不合法，拒绝登录")
	}
	serverName := ""
	serverInfo, infoErr := a.GetYggdrasilServerInfo(serverURL)
	if infoErr == nil {
		if safe, ok := validateYggServerName(serverInfo.Meta.ServerName); ok && safe != "" {
			serverName = safe
		}
	}
	return &ExternalAuthData{
		ServerURL:   serverURL,
		AccessToken: authResp.AccessToken,
		ClientToken: authResp.ClientToken,
		UUID:        profile.UUID,
		Username:    profile.Name,
		Password:    password,
		ServerName:  serverName,
	}, nil
}

// RefreshExternalToken 刷新外置登录令牌
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

// authlibJarMaxBytes 限制 authlib-injector.jar 下载体积。
// 正常 jar 只有约 1 MiB，给到 64 MiB 只是为正常升级留余量；
// 再大基本就是恶意/错误响应，必须在它炸磁盘前中止。
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

// downloadAuthlibJarFromCandidates 按顺序尝试候选地址，下载到临时文件，
// 强制 SHA-256 校验通过、体积不超限后才 rename 到目标路径并写入侧车。
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
			tmp, err := os.OpenFile(filepath.Join(dir, ".authlib-*.jar.tmp"),
				os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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

	if _, statErr := os.Stat(jarPath); statErr == nil {
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
