package main

import (
	"crypto"
	"crypto/hmac"
	"os"
	"strings"
)

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
