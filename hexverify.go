package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

// equalHexDigest 判断两段十六进制摘要是否等价。
// 外部清单（Mojang / Modrinth / authlib）给的大小写并不统一，
// 逐字符比较会把全大写的合法摘要判成篡改；这里只折叠大小写与首尾空白。
func equalHexDigest(got, want string) bool {
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))
}

// digestFileHex 用指定哈希算法对文件做一次顺序读，返回小写十六进制摘要。
func digestFileHex(file *os.File, newHash func() hash.Hash) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := newHash()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileSHA1Matches 校验文件 SHA1 是否等于期望值；Mojang 清单仍以 SHA1 为权威算法。
func fileSHA1Matches(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	got, err := digestFileHex(f, sha1.New)
	if err != nil {
		return false
	}
	return equalHexDigest(got, want)
}

// fileSHA512Matches 校验文件 SHA512 是否等于期望值。
func fileSHA512Matches(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	got, err := digestFileHex(f, sha512.New)
	if err != nil {
		return false
	}
	return equalHexDigest(got, want)
}

// verifyFileDigest 按算法名（sha1/sha512）校验文件摘要，返回不一致时的描述。
func verifyFileDigest(path, algo, want string) (string, error) {
	var newHash func() hash.Hash
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha1":
		newHash = sha1.New
	case "sha512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("不支持的摘要算法: %s", algo)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	got, err := digestFileHex(f, newHash)
	if err != nil {
		return "", err
	}
	if equalHexDigest(got, want) {
		return "", nil
	}
	return got, nil
}
