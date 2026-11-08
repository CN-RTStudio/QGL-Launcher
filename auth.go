package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/crypto/pbkdf2"
)

const (
	oauthClientID = "" //修改为你的client id
	oauthScope    = "XboxLive.signin offline_access"

	// Microsoft OAuth endpoints
	deviceCodeURL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
	tokenURL      = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

	// Xbox Live endpoints
	xblAuthURL  = "https://user.auth.xboxlive.com/user/authenticate"
	xstsAuthURL = "https://xsts.auth.xboxlive.com/xsts/authorize"

	// Minecraft services endpoints
	mcLoginURL       = "https://api.minecraftservices.com/authentication/login_with_xbox"
	mcEntitlementURL = "https://api.minecraftservices.com/entitlements/mcstore"
	mcProfileURL     = "https://api.minecraftservices.com/minecraft/profile"

	// 安全加固: PBKDF2 参数
	pbkdf2Iterations = 100000
	pbkdf2KeyLength  = 32
	pbkdf2Salt       = "OpenQGL_Salt_2024!@#"

	// authJSONMaxBytes 限制每个认证 JSON 响应最多 1 MiB。
	// 认证接口本应返回小体量的 token 结构，超过这个尺寸基本就是恶意响应或错误页面。
	authJSONMaxBytes = 1 << 20

	// 设备码轮询参数。interval / expires_in 都来自微软的响应，不能无条件信任：
	// 被劫持或畸形的响应可以给个超大值，让轮询 goroutine 睡几个小时、或把登录
	// 有效期拉到几天。这里按官方正常范围（间隔 5s、设备码约 15min 失效）钳制。
	deviceCodeMinInterval = 5 * time.Second
	deviceCodeMaxInterval = 5 * time.Minute
	deviceCodeDefaultTTL  = 5 * time.Minute
	deviceCodeMaxTTL      = 15 * time.Minute
	// slow_down 要求每次间隔 +5s，但加多少次必须有上限，否则服务器一直回
	// slow_down 就能把这个 goroutine 无限期挂住。
	deviceCodeMaxSlowDowns = 60
	// 网络错误 / 429 / 5xx 属于瞬时故障，连续这么多次仍不恢复就放弃登录，
	// 而不是在后台无限重试。
	deviceCodeMaxTransientErrors = 8
	// token expires_in 的合理上限（一年）。正常 MSA/MC 令牌都是 24h，
	// 给极大值只会把过期时间写到未来很久，掩盖"该刷新了"的判断。
	tokenMaxLifetimeSeconds = 365 * 24 * 3600
	tokenDefaultLifetimeSec = 24 * 3600
)

// MSAuthData 微软认证数据（存储在用户目录的 ms_auth.json）
type MSAuthData struct {
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken"`
	MCAccessToken string `json:"mcAccessToken"`
	UUID          string `json:"uuid"`
	Username      string `json:"username"`
	ExpiresAt     int64  `json:"expiresAt"`
	MCExpiresAt   int64  `json:"mcExpiresAt"`
}

// MSAuthDataEncrypted 加密存储的认证数据格式
type MSAuthDataEncrypted struct {
	Username string `json:"username"` // 用户名不加密
	Data     string `json:"data"`     // 其余字段加密后的 base64 字符串
}

// ExternalAuthDataEncrypted 外置认证数据加密存储格式
type ExternalAuthDataEncrypted struct {
	ServerName string `json:"serverName"` // 服务器名称不加密
	Data       string `json:"data"`       // 其余字段加密后的 base64 字符串
}

// getEncryptionKey 使用 PBKDF2 派生 32 字节 AES 密钥
// 使用 UMFS 作为底层哈希函数（bool-hybrid-array 生态）
// salt 为每用户随机持久化盐（ms_auth.salt）；为空时回退到旧硬编码盐以兼容老数据
func getEncryptionKey(username string, salt []byte) []byte {
	if len(salt) == 0 {
		salt = []byte(pbkdf2Salt + username)
	} else {
		combined := make([]byte, 0, len(salt)+len(username))
		combined = append(combined, salt...)
		combined = append(combined, username...)
		salt = combined
	}
	// pbkdf2.Key 要求 func() hash.Hash；NewUMFSHash 返回具体类型 *UMFSHash，
	// Go 的函数类型不支持返回值协变，这里用闭包适配（UMFSHash 已实现 hash.Hash）。
	return pbkdf2.Key([]byte(username), salt, pbkdf2Iterations, pbkdf2KeyLength, func() hash.Hash {
		return NewUMFSHash()
	})
}

// maxAuthSaltBytes 是本地认证盐文件读取上限：盐本身仅 16 字节，取 1KiB 极宽值。
const maxAuthSaltBytes int64 = 1 << 10

// loadOrCreateAuthSalt 读取用户目录下的随机盐文件；不存在且 create=true 时生成 16 字节随机盐并落盘。
// 读老数据时若文件不存在，返回 (nil, false)，调用方回退到旧硬编码盐。
func loadOrCreateAuthSalt(saltPath string, create bool) ([]byte, bool, error) {
	// 盐文件也不允许是预置的符号链接，否则攻击者可以喂给程序一个已知盐。
	if bad, err := isSymlinkOrSpecial(saltPath); err != nil {
		return nil, false, err
	} else if bad {
		return nil, false, fmt.Errorf("盐文件是符号链接或非普通文件，已拒绝: %s", saltPath)
	}
	// 盐正常就是 16 字节随机串，取 1KiB 这种极宽上限只拦被塞成超大文件的异常读入；
	// 读取失败（含超量）沿用旧逻辑：create 时重新生成，否则回退旧硬编码盐。
	if data, err := readBoundedFile(saltPath, maxAuthSaltBytes); err == nil && len(data) >= 16 {
		return data, false, nil
	}
	if !create {
		return nil, false, nil
	}
	// 使用 mt_xor25（bool-hybrid-array 生态）生成 16 字节随机盐
	salt := mtXOR25Bytes(16)
	if err := secureWritePrivateFile(saltPath, salt); err != nil {
		return nil, false, err
	}
	return salt, true, nil
}

// aesGCMEncrypt 使用 AES-GCM 加密数据，返回 base64 编码的密文
func aesGCMEncrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// aesGCMDecrypt 使用 AES-GCM 解密 base64 编码的密文
func aesGCMDecrypt(encoded string, key []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// 安全加固: 复用全局 safeHTTPClient（TLS 1.2+，30秒超时，Dial 层拦私网）
var httpClient = safeHTTPClient()

// yggHTTPClient 仅供用户主动配置的 Yggdrasil 外置登录使用：本地调试皮肤站
// 允许跑在 loopback/局域网，但绝不能用于远程元数据给出的 URL。
var yggHTTPClient = localHTTPClient()

// readAuthJSON 用 LimitReader 限制响应体大小后再读 JSON，
// 防止恶意服务器返回几个 GiB 数据把内存吃爆。
func readAuthJSON(resp *http.Response) ([]byte, error) {
	limited := io.LimitReader(resp.Body, authJSONMaxBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= authJSONMaxBytes {
		return nil, fmt.Errorf("响应体超过 %d 字节上限", authJSONMaxBytes)
	}
	return body, nil
}

// DeviceCodeResponse 设备代码响应
type DeviceCodeResponse struct {
	UserCode         string `json:"user_code"`
	DeviceCode       string `json:"device_code"`
	VerificationURL  string `json:"verification_uri"`
	ExpiresIn        int    `json:"expires_in"`
	Interval         int    `json:"interval"`
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// XBLAuthResponse Xbox Live 认证响应
type XBLAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

// XSTSAuthResponse XSTS 认证响应
type XSTSAuthResponse struct {
	IssueInstant  string `json:"IssueInstant"`
	NotAfter      string `json:"NotAfter"`
	Token         string `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
	ErrorCode int    `json:"XErr"`
	Message   string `json:"Message"`
}

// MCLoginResponse Minecraft 登录响应
type MCLoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Username    string `json:"username"`
	// 错误字段
	Error            string `json:"error"`
	ErrorMessage     string `json:"errorMessage"`
	DeveloperMessage string `json:"developerMessage"`
}

// MCProfileResponse Minecraft 玩家档案响应
type MCProfileResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MCEntitlementResponse Minecraft 所有权验证响应
type MCEntitlementResponse struct {
	Items []struct {
		Name string `json:"name"`
	} `json:"items"`
}

// clampPollInterval 钳制设备码轮询间隔：下限 5s（微软规定不得更快，否则会
// 被判定滥用），上限 5min（防远程响应给超大 interval 挂住 goroutine）。
func clampPollInterval(seconds int) time.Duration {
	if seconds < int(deviceCodeMinInterval/time.Second) {
		return deviceCodeMinInterval
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxInterval {
		return deviceCodeMaxInterval
	}
	return d
}

// clampDeviceTTL 钳制设备码有效期：非正用默认 5min，最大不超过 15min。
func clampDeviceTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return deviceCodeDefaultTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxTTL {
		return deviceCodeMaxTTL
	}
	return d
}

// tokenExpiryUnix 根据远程给的 expires_in 计算过期时间戳。
// 非正值回退 24h（MSA/MC 令牌的常规有效期），超大值钳到一年，避免把刷新
// 判断写到错误的未来。
func tokenExpiryUnix(now time.Time, seconds int) int64 {
	if seconds <= 0 {
		seconds = tokenDefaultLifetimeSec
	}
	if seconds > tokenMaxLifetimeSeconds {
		seconds = tokenMaxLifetimeSeconds
	}
	return now.Add(time.Duration(seconds) * time.Second).Unix()
}

// isAllowedVerificationURL 限定设备码验证页只能落在微软自家域名。
// 仅校验 https:// 前缀并不够：被劫持的响应可以给一个 https:// 钓鱼站，
// 用户在系统浏览器里输入的 user code 会直接进攻击者手里。这里再收紧：
// 必须是 https、无 userinfo、主机为 microsoft.com / live.com（含子域，
// 官方设备码验证页为 www.microsoft.com/link、login.live.com 等）。
func isAllowedVerificationURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	return host == "microsoft.com" || strings.HasSuffix(host, ".microsoft.com") ||
		host == "microsoftonline.com" || strings.HasSuffix(host, ".microsoftonline.com") ||
		host == "live.com" || strings.HasSuffix(host, ".live.com")
}

// StartMicrosoftLogin 开始微软登录流程（Device Code Flow）
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
