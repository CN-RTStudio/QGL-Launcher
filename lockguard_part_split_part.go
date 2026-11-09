package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

func itoaSafe(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func hmacEqualHex(a, b string) bool {
	if len(a) != 64 || len(b) != 64 {
		return false
	}
	da, ea := hex.DecodeString(a)
	db, eb := hex.DecodeString(b)
	if ea != nil || eb != nil {
		return false
	}
	return subtle.ConstantTimeCompare(da, db) == 1
}

// errText 定义在 umfs.go（type errText string），这里直接复用；
// errText("...") 已满足 error 接口，无需再包装。

// base64 import guard（摘要负载可选 base64 形态时使用）
var _ = base64.StdEncoding
