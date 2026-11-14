package main

import (
	"crypto"
	"crypto/hmac"
	"os"
	"strings"
)

const maxAuthlibMetaBytes int64 = 1 << 20

type authlibMeta struct {
	SHA256 string `json:"sha256"` // 官方 latest.json 给出的权威 SHA-256（小写）
	Size   int64  `json:"size"`   // 字节数，先做廉价预检
}

func authlibMetaPath(jarPath string) string {
	return jarPath + ".sha256meta"
}

func loadAuthlibMeta(jarPath string) (authlibMeta, bool) {
	var m authlibMeta
	// 侧车是本地小 JSON，走有界读取：缺失 / 损坏 / 被改成超大体积都判为不可信，
	// 绝不无界整体读入；超量由 readLocalJSONBounded 写安全审计。
	if err := readLocalJSONBounded(authlibMetaPath(jarPath), &m, maxAuthlibMetaBytes, "authlib侧车元数据"); err != nil {
		return m, false
	}
	if m.SHA256 == "" || m.Size <= 0 {
		return m, false
	}
	return m, true
}

// saveAuthlibMeta 在 jar 已通过官方 SHA-256 校验后原子写入侧车。
func saveAuthlibMeta(jarPath, expectedSHA256 string, size int64) error {
	m := authlibMeta{SHA256: expectedSHA256, Size: size}
	// 统一走有界原子私有写内核（0600 + fsync + rename + 拒符号链接 + 父目录收权），
	// 替换此前手写 tmp→rename（缺 fsync / 符号链接防护）。
	return writePrivateJSON(authlibMetaPath(jarPath), m)
}

func removeAuthlibMeta(jarPath string) {
	_ = os.Remove(authlibMetaPath(jarPath))
}

// sha256FileHex 以流式方式计算文件的 SHA-256 小写十六进制摘要，
// 不再把整个 jar 读进内存（jar 可能数 MB～数十 MB）。
func sha256FileHex(path string) (string, error) {
	return hashFileHex(crypto.SHA256, path)
}

// verifyAuthlibJar 校验已存在的 jar 是否可直接复用：
// 侧车必须存在、尺寸必须一致、重新计算的 SHA-256 必须与侧车严格相等。
// 任何一项不满足都返回 false，由调用方删除并重新下载，绝不降级放行。
func verifyAuthlibJar(jarPath, expectedSHA256 string) bool {
	info, err := os.Stat(jarPath)
	if err != nil || info.Size() <= 0 {
		return false
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expected == "" {
		return false
	}
	meta, ok := loadAuthlibMeta(jarPath)
	if !ok {
		return false
	}
	if meta.Size != info.Size() {
		return false
	}
	if !hmac.Equal([]byte(meta.SHA256), []byte(expected)) {
		return false
	}
	got, err := sha256FileHex(jarPath)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(got), []byte(expected))
}
