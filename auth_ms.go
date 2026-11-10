package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
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
type MCProfileResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type MCEntitlementResponse struct {
	Items []struct {
		Name string `json:"name"`
	} `json:"items"`
}

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
