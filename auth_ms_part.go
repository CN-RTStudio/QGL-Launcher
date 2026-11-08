package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
