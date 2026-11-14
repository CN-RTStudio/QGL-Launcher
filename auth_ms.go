package main

import (
	"golang.org/x/crypto/pbkdf2"
	"hash"
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
