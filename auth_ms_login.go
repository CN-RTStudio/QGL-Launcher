package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) StartMicrosoftLogin() (string, error) {
	if !authRateLimiter.Allow("ms-start") {
		return "", fmt.Errorf("登录请求过于频繁，请稍后再试")
	}
	data := url.Values{
		"client_id": {oauthClientID},
		"scope":     {oauthScope},
	}
	resp, err := httpClient.PostForm(deviceCodeURL, data)
	if err != nil {
		return "", fmt.Errorf("请求设备代码失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return "", fmt.Errorf("读取设备代码响应失败: %v", err)
	}
	var dcResp DeviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return "", fmt.Errorf("解析设备代码响应失败: %v (原始: %s)", err, string(body))
	}
	if dcResp.Error != "" {
		return "", fmt.Errorf("设备代码错误: %s - %s", dcResp.Error, dcResp.ErrorDescription)
	}

	// 验证页必须是 https 且落在微软自家域名，避免被劫持响应导向钓鱼站骗取 user code。
	if !isAllowedVerificationURL(dcResp.VerificationURL) {
		return "", fmt.Errorf("验证 URL 不在微软可信域名内，拒绝打开")
	}

	// 安全修复：不要走 cmd.exe /c start，那会把 URL 拼进 shell 命令行，
	// 一旦 VerificationURL 含 & 或 ^ 等 cmd 元字符就可能被解析成命令。
	// runtime.BrowserOpenURL 直接交给系统默认浏览器，不经过 shell。
	runtime.BrowserOpenURL(a.ctx, dcResp.VerificationURL)

	runtime.ClipboardSetText(a.ctx, dcResp.UserCode)

	go a.pollMicrosoftToken(dcResp)

	result := fmt.Sprintf("%s|%s", dcResp.VerificationURL, dcResp.UserCode)
	return result, nil
}

// backoffDeviceInterval 把轮询间隔翻倍退避（下限 5s、上限 5min）。
func backoffDeviceInterval(cur time.Duration) time.Duration {
	next := cur * 2
	if next < deviceCodeMinInterval {
		return deviceCodeMinInterval
	}
	if next > deviceCodeMaxInterval {
		return deviceCodeMaxInterval
	}
	return next
}

// parseRetryAfterDelay 解析 RFC 7231 的 Retry-After（delta-seconds 或 HTTP 日期），
// 非法 / 零 / 负值返回 0；正值统一钳到轮询上限，避免服务器让我们睡几个小时。
func parseRetryAfterDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if sec, err := strconv.Atoi(value); err == nil {
		if sec <= 0 {
			return 0
		}
		d := time.Duration(sec) * time.Second
		if d > deviceCodeMaxInterval {
			return deviceCodeMaxInterval
		}
		return d
	}
	if t, err := http.ParseTime(value); err == nil {
		d := time.Until(t)
		if d <= 0 || d > deviceCodeMaxInterval {
			if d <= 0 {
				return 0
			}
			return deviceCodeMaxInterval
		}
		return d
	}
	return 0
}

// pollMicrosoftToken 轮询微软令牌，到达设备码过期时间后自动退出。
//
// 韧性处理（interval / ttl 已在 clampXxx 中钳制）：
//   - 网络错误、5xx、429 属于瞬时故障，按翻倍退避重试，并尊重 Retry-After；
//   - 连续 deviceCodeMaxTransientErrors 次瞬时故障就报错退出，不无限忙轮询；
//   - authorization_pending / slow_down 说明服务器本身健康，清零瞬时故障计数。
func (a *App) pollMicrosoftToken(dc DeviceCodeResponse) {
	interval := clampPollInterval(dc.Interval)
	deadline := time.Now().Add(clampDeviceTTL(dc.ExpiresIn))
	slowDowns := 0
	transientErrors := 0

	// sleepFor 等待下一次轮询；应用退出（ctx.Done）时立即结束。
	// 返回 false 表示已到截止时间或应用关闭，调用方应退出循环。
	sleepFor := func(d time.Duration) bool {
		if d > deviceCodeMaxInterval {
			d = deviceCodeMaxInterval
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-a.ctx.Done():
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		return true
	}

	failTransient := func() bool {
		transientErrors++
		return transientErrors >= deviceCodeMaxTransientErrors
	}

	for {
		if !sleepFor(interval) {
			if a.ctx.Err() != nil {
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
			return
		}
		data := url.Values{
			"client_id":   {oauthClientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
		}
		resp, err := httpClient.PostForm(tokenURL, data)
		if err != nil {
			if failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录服务器连续无响应，请检查网络后重试")
				return
			}
			interval = backoffDeviceInterval(interval)
			continue
		}

		// 429 / 5xx：优先尊重 Retry-After，否则指数退避；都不消费设备码语义。
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			retry := parseRetryAfterDelay(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			if failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录服务器暂时不可用，请稍后重试")
				return
			}
			if retry > 0 {
				interval = retry
			} else {
				interval = backoffDeviceInterval(interval)
			}
			continue
		}

		body, readErr := readAuthJSON(resp)
		resp.Body.Close()
		var tokenResp TokenResponse
		if readErr != nil || json.Unmarshal(body, &tokenResp) != nil {
			// 4xx 还返回无法解析的内容，基本是被代理/门户劫持，直接失败；
			// 2xx 但内容畸形则按瞬时故障退避重试。
			if resp.StatusCode >= 400 || failTransient() {
				runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录响应异常 (HTTP %d)", resp.StatusCode))
				return
			}
			interval = backoffDeviceInterval(interval)
			continue
		}
		transientErrors = 0

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				continue
			}
			if tokenResp.Error == "slow_down" {
				// 每次 +5s，但有总次数上限；到上限按设备码过期处理，
				// 防止服务器持续 slow_down 把 goroutine 无限挂住。
				if slowDowns >= deviceCodeMaxSlowDowns {
					runtime.EventsEmit(a.ctx, "msLoginError", "登录轮询超时，请重新尝试")
					return
				}
				slowDowns++
				interval += 5 * time.Second
				if interval > deviceCodeMaxInterval {
					interval = deviceCodeMaxInterval
				}
				continue
			}
			if tokenResp.Error == "expired_token" {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录失败: %s", tokenResp.ErrorDescription))
			return
		}
		a.completeMicrosoftLogin(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		return
	}
}

// completeMicrosoftLogin 完成微软登录的后续步骤（Xbox → Minecraft）
func (a *App) completeMicrosoftLogin(msAccessToken string, msRefreshToken string, msExpiresIn int) {
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证 Xbox Live...")
	xblToken, _, err := a.authXBL(msAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("Xbox Live 验证失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取 XSTS 令牌...")
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("XSTS 验证失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在登录 Minecraft...")
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("Minecraft 登录失败: %v", err))
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证游戏所有权...")
	hasGame, err := a.checkMCEntitlement(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("验证游戏所有权失败: %v", err))
		return
	}
	if !hasGame {
		runtime.EventsEmit(a.ctx, "msLoginError", "该微软账号未购买 Minecraft Java 版，或 Xbox Game Pass 已过期")
		return
	}
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取玩家档案...")
	profile, err := a.getMCProfile(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("获取玩家档案失败: %v", err))
		return
	}

	now := time.Now()
	authData := MSAuthData{
		AccessToken:   msAccessToken,
		RefreshToken:  msRefreshToken,
		MCAccessToken: mcAccessToken,
		UUID:          profile.ID,
		Username:      profile.Name,
		// MSA 令牌与 MC 令牌各自独立，过期时间必须分别记录：
		// ExpiresAt 用微软令牌 expires_in，MCExpiresAt 用 MC 登录返回的值。
		ExpiresAt:   tokenExpiryUnix(now, msExpiresIn),
		MCExpiresAt: tokenExpiryUnix(now, mcExpiresIn),
	}

	if err := a.CreatePremiumUser(profile.Name, authData); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("创建用户失败: %v", err))
		return
	}

	if err := a.SetCurrentUser(profile.Name); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Errorf("设置当前用户失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginSuccess", profile.Name)
}

// authXBL Step 2: 用 OAuth Token 换取 XBL Token
func (a *App) authXBL(accessToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]string{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + accessToken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	resp, err := httpClient.Post(xblAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XBL 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XBL 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var xblResp XBLAuthResponse
	if err := json.Unmarshal(respBody, &xblResp); err != nil {
		return "", "", fmt.Errorf("XBL 响应解析失败: %s", string(respBody))
	}
	if xblResp.Token == "" {
		return "", "", fmt.Errorf("XBL 响应中缺少 Token")
	}
	if len(xblResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XBL 响应中缺少 UHS")
	}
	return xblResp.Token, xblResp.DisplayClaims.XUI[0].UHS, nil
}

// authXSTS Step 3: 用 XBL Token 换取 XSTS Token + UHS
func (a *App) authXSTS(xblToken string) (string, string, error) {
	payload := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	resp, err := httpClient.Post(xstsAuthURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("XSTS 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return "", "", err
	}
	var xstsErrResp struct {
		XErr    int    `json:"XErr"`
		Message string `json:"Message"`
	}
	json.Unmarshal(respBody, &xstsErrResp)
	if xstsErrResp.XErr != 0 {
		switch xstsErrResp.XErr {
		case 2148916233:
			return "", "", fmt.Errorf("该微软账号未关联 Xbox 账号")
		case 2148916235:
			return "", "", fmt.Errorf("Xbox Live 在您所在地区不可用")
		case 2148916236:
			return "", "", fmt.Errorf("该 Xbox 账号需要成人确认才能登录")
		case 2148916237:
			return "", "", fmt.Errorf("该 Xbox 账号已被封禁")
		case 2148916238:
			return "", "", fmt.Errorf("该账号是未成年人账号，无法完成登录")
		default:
			return "", "", fmt.Errorf("XSTS 错误 %d: %s", xstsErrResp.XErr, xstsErrResp.Message)
		}
	}
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("XSTS 请求失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var xstsResp XSTSAuthResponse
	if err := json.Unmarshal(respBody, &xstsResp); err != nil {
		return "", "", fmt.Errorf("XSTS 响应解析失败: %s", string(respBody))
	}
	if xstsResp.Token == "" {
		return "", "", fmt.Errorf("XSTS 响应中缺少 Token")
	}
	if len(xstsResp.DisplayClaims.XUI) == 0 {
		return "", "", fmt.Errorf("XSTS 响应中缺少 UHS")
	}
	return xstsResp.Token, xstsResp.DisplayClaims.XUI[0].UHS, nil
}

// authMinecraft Step 4: 用 XSTS Token 换取 Minecraft Access Token
func (a *App) authMinecraft(xstsToken string, uhs string) (string, int, error) {
	identityToken := fmt.Sprintf("XBL3.0 x=%s;%s", uhs, xstsToken)
	payload := map[string]string{
		"identityToken": identityToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", 0, err
	}
	resp, err := httpClient.Post(mcLoginURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := readAuthJSON(resp)
	if err != nil {
		return "", 0, err
	}
	var mcErrResp MCLoginResponse
	json.Unmarshal(respBody, &mcErrResp)
	if mcErrResp.Error != "" {
		errMsg := mcErrResp.ErrorMessage
		if errMsg == "" {
			errMsg = mcErrResp.DeveloperMessage
		}
		if errMsg == "" {
			errMsg = mcErrResp.Error
		}
		return "", 0, fmt.Errorf("Minecraft 登录失败: %s (HTTP %d)", errMsg, resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("Minecraft 登录失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var mcResp MCLoginResponse
	if err := json.Unmarshal(respBody, &mcResp); err != nil {
		return "", 0, fmt.Errorf("Minecraft 登录响应解析失败: %s", string(respBody))
	}
	if mcResp.AccessToken == "" {
		return "", 0, fmt.Errorf("未获取到 Minecraft Access Token (响应: %s)", string(respBody))
	}
	expiresIn := mcResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 86400
	}
	return mcResp.AccessToken, expiresIn, nil
}

// checkMCEntitlement Step 5: 验证是否持有 Minecraft
func (a *App) checkMCEntitlement(mcAccessToken string) (bool, error) {
	req, err := http.NewRequest("GET", mcEntitlementURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return false, err
	}
	var entResp MCEntitlementResponse
	if err := json.Unmarshal(body, &entResp); err != nil {
		return false, err
	}
	return len(entResp.Items) > 0, nil
}

// getMCProfile Step 6: 获取玩家档案
func (a *App) getMCProfile(mcAccessToken string) (*MCProfileResponse, error) {
	req, err := http.NewRequest("GET", mcProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("获取玩家档案失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}
	var profile MCProfileResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("解析玩家档案失败: %s", string(body))
	}
	if profile.ID == "" || profile.Name == "" {
		return nil, fmt.Errorf("玩家档案为空: %s", string(body))
	}
	return &profile, nil
}

// RefreshMicrosoftToken 刷新微软令牌
func (a *App) RefreshMicrosoftToken(username string) error {
	if !authRateLimiter.Allow("ms-refresh-" + username) {
		return fmt.Errorf("刷新令牌过于频繁，请稍后再试")
	}
	if err := validateUsername(username); err != nil {
		return err
	}
	authData, err := a.GetMSAuthData(username)
	if err != nil {
		return fmt.Errorf("读取认证数据失败: %v", err)
	}
	if authData.RefreshToken == "" {
		return fmt.Errorf("无刷新令牌，请重新登录")
	}
	if time.Now().Unix() < authData.MCExpiresAt-60 {
		return nil
	}
	data := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {authData.RefreshToken},
		"scope":         {oauthScope},
	}
	resp, err := httpClient.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("刷新令牌请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := readAuthJSON(resp)
	if err != nil {
		return err
	}
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return err
	}
	if tokenResp.Error != "" {
		return fmt.Errorf("刷新令牌失败: %s", tokenResp.ErrorDescription)
	}
	xblToken, _, err := a.authXBL(tokenResp.AccessToken)
	if err != nil {
		return err
	}
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		return err
	}
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		return err
	}
	now := time.Now()
	authData.AccessToken = tokenResp.AccessToken
	// 微软刷新响应可能不重复下发 refresh_token（令牌轮转但本响应缺字段）；
	// 此时绝不能用空串覆盖掉旧的 refresh_token，否则下一次刷新会直接废掉。
	if tokenResp.RefreshToken != "" {
		authData.RefreshToken = tokenResp.RefreshToken
	}
	authData.MCAccessToken = mcAccessToken
	authData.ExpiresAt = tokenExpiryUnix(now, tokenResp.ExpiresIn)
	authData.MCExpiresAt = tokenExpiryUnix(now, mcExpiresIn)
	return a.SaveMSAuthData(username, authData)
}

// GetMSAuthData 获取微软认证数据（自动处理加密/明文兼容）
func (a *App) GetMSAuthData(username string) (*MSAuthData, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	authPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.json")
	// 凭据文件走有界读取（默认 64MiB 本地文本上限）并拒绝符号链接，防止超大 / 预置链接读入。
	data, err := readBoundedFile(authPath, localTextConfigMaxBytes)
	if err != nil {
		return nil, err
	}
	var encData MSAuthDataEncrypted
	if err := json.Unmarshal(data, &encData); err == nil && encData.Data != "" {
		saltPath := filepath.Join(a.GetUsersDir(), username, "ms_auth.salt")
		salt, _, _ := loadOrCreateAuthSalt(saltPath, false)
		key := getEncryptionKey(username, salt)
		decrypted, err := aesGCMDecrypt(encData.Data, key)
		if err != nil {
			return nil, fmt.Errorf("解密认证数据失败: %w", err)
		}
		var authData MSAuthData
		if err := json.Unmarshal(decrypted, &authData); err != nil {
			return nil, fmt.Errorf("解析解密后的认证数据失败: %w", err)
		}
		authData.Username = username
		return &authData, nil
	}
	var authData MSAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		return nil, fmt.Errorf("解析认证数据失败: %w", err)
	}
	return &authData, nil
}

// SaveMSAuthData 保存微软认证数据（加密存储，username 以外的字段全部加密）
func (a *App) SaveMSAuthData(username string, authData *MSAuthData) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return err
	}
	encryptPayload := map[string]interface{}{
		"accessToken":   authData.AccessToken,
		"refreshToken":  authData.RefreshToken,
		"mcAccessToken": authData.MCAccessToken,
		"uuid":          authData.UUID,
		"expiresAt":     authData.ExpiresAt,
		"mcExpiresAt":   authData.MCExpiresAt,
	}
	payloadBytes, err := json.Marshal(encryptPayload)
	if err != nil {
		return err
	}
	saltPath := filepath.Join(userDir, "ms_auth.salt")
	salt, _, _ := loadOrCreateAuthSalt(saltPath, true)
	key := getEncryptionKey(username, salt)
	encrypted, err := aesGCMEncrypt(payloadBytes, key)
	if err != nil {
		return fmt.Errorf("加密认证数据失败: %w", err)
	}
	encData := MSAuthDataEncrypted{
		Username: username,
		Data:     encrypted,
	}
	data, err := json.MarshalIndent(encData, "", "  ")
	if err != nil {
		return err
	}
	// 微软令牌是最高敏感级数据：原子写、0600、拒绝符号链接写穿
	return secureWritePrivateFile(filepath.Join(userDir, "ms_auth.json"), data)
}
