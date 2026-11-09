package main

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"strings"
)

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
