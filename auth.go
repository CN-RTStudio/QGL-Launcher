package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
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

//为了防止加密逻辑被获取，加密逻辑已更改简化，如果你的产品需要上线必须修改逻辑为更安全的!!!!!!!
// getEncryptionKey 根据用户名+OQL生成 32 字节 AES 密钥
func getEncryptionKey(username string) []byte {
	raw := username + "OQL"
	// 简单派生：循环异或混合到 32 字节
	key := make([]byte, 32)
	for i := 0; i < len(raw); i++ {
		key[i%32] ^= raw[i]
	}
	for round := 0; round < 64; round++ {
		for i := 0; i < 32; i++ {
			key[i] = key[i] ^ key[(i+1)%32] ^ byte(round)
		}
	}
	return key
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
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	ExpiresIn       int    `json:"expires_in"`
	TokenType       string `json:"token_type"`
	Scope           string `json:"scope"`
	Error           string `json:"error"`
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

// StartMicrosoftLogin 开始微软登录流程（Device Code Flow）
func (a *App) StartMicrosoftLogin() (string, error) {
	// Step 1: 请求设备代码
	data := url.Values{
		"client_id": {oauthClientID},
		"scope":     {oauthScope},
	}

	resp, err := http.PostForm(deviceCodeURL, data)
	if err != nil {
		return "", fmt.Errorf("请求设备代码失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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

	// 自动打开验证链接
	openCmd := exec.Command("cmd", "/c", "start", dcResp.VerificationURL)
	openCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	openCmd.Start()

	// 自动复制用户代码到剪贴板
	runtime.ClipboardSetText(a.ctx, dcResp.UserCode)

	// 在后台轮询令牌
	go a.pollMicrosoftToken(dcResp)

	// 返回用户需要访问的URL和代码
	result := fmt.Sprintf("%s|%s", dcResp.VerificationURL, dcResp.UserCode)
	return result, nil
}

// pollMicrosoftToken 轮询微软令牌
func (a *App) pollMicrosoftToken(dc DeviceCodeResponse) {
	interval := 5
	if dc.Interval > 0 {
		interval = dc.Interval
	}

	for {
		time.Sleep(time.Duration(interval) * time.Second)

		data := url.Values{
			"client_id":   {oauthClientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
		}

		resp, err := http.PostForm(tokenURL, data)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tokenResp TokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			continue
		}

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				continue
			}
			if tokenResp.Error == "slow_down" {
				interval += 5
				continue
			}
			if tokenResp.Error == "expired_token" {
				runtime.EventsEmit(a.ctx, "msLoginError", "登录已过期，请重新尝试")
				return
			}
			runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("登录失败: %s", tokenResp.ErrorDescription))
			return
		}

		// 获取到 Microsoft Access Token，继续后续步骤
		a.completeMicrosoftLogin(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		return
	}
}

// completeMicrosoftLogin 完成微软登录的后续步骤（Xbox → Minecraft）
func (a *App) completeMicrosoftLogin(msAccessToken string, msRefreshToken string, msExpiresIn int) {
	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证 Xbox Live...")

	// Step 2: OAuth Token → XBL Token
	xblToken, _, err := a.authXBL(msAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Xbox Live 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取 XSTS 令牌...")

	// Step 3: XBL Token → XSTS Token + UHS
	xstsToken, xstsUHS, err := a.authXSTS(xblToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("XSTS 验证失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在登录 Minecraft...")

	// Step 4: XSTS Token → Minecraft Access Token
	// 注意：使用 XSTS 返回的 UHS，而不是 XBL 的 UHS
	mcAccessToken, mcExpiresIn, err := a.authMinecraft(xstsToken, xstsUHS)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("Minecraft 登录失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在验证游戏所有权...")

	// Step 5: 验证是否持有 Minecraft
	hasGame, err := a.checkMCEntitlement(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("验证游戏所有权失败: %v", err))
		return
	}
	if !hasGame {
		runtime.EventsEmit(a.ctx, "msLoginError", "该微软账号未购买 Minecraft Java 版，或 Xbox Game Pass 已过期")
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginProgress", "正在获取玩家档案...")

	// Step 6: 获取玩家档案
	profile, err := a.getMCProfile(mcAccessToken)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("获取玩家档案失败: %v", err))
		return
	}

	// 保存认证数据
	authData := MSAuthData{
		AccessToken:   msAccessToken,
		RefreshToken:  msRefreshToken,
		MCAccessToken: mcAccessToken,
		UUID:          profile.ID,
		Username:      profile.Name,
		ExpiresAt:     time.Now().Add(time.Duration(msExpiresIn) * time.Second).Unix(),
		MCExpiresAt:   time.Now().Add(time.Duration(mcExpiresIn) * time.Second).Unix(),
	}

	// 创建正版用户（返回用户标识 dir）
	dir, err := a.CreatePremiumUser(profile.Name, authData)
	if err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("创建用户失败: %v", err))
		return
	}

	// 设置为当前用户
	if err := a.SetCurrentUser(dir); err != nil {
		runtime.EventsEmit(a.ctx, "msLoginError", fmt.Sprintf("设置当前用户失败: %v", err))
		return
	}

	runtime.EventsEmit(a.ctx, "msLoginSuccess", profile.Name)
}

// authXBL Step 2: 用 OAuth Token 换取 XBL Token
