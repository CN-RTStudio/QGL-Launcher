package main

import (
	"golang.org/x/crypto/pbkdf2"
	"hash"
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
