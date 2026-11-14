package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func newLockState(pin string) (lockState, error) {
	salt := make([]byte, 16)
	if _, err := randRead(salt); err != nil {
		return lockState{}, err
	}
	sum := umfsLockDigest([]byte(pin), salt)
	return lockState{
		HMACHex: hex.EncodeToString(sum),
		SaltHex: hex.EncodeToString(salt),
	}, nil
}

// normalizeLockState 读取时兜底：字段缺失/类型非法一律置零，绝不让坏负载
// 撑起一把“永远打不开”的锁。
func normalizeLockState(raw []byte) lockState {
	var st lockState
	if len(raw) == 0 {
		return st
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return lockState{}
	}
	if st.HMACHex == "" || st.SaltHex == "" {
		return lockState{}
	}
	if len(st.HMACHex) != 64 || len(st.SaltHex) != 32 {
		return lockState{}
	}
	if st.Fails < 0 {
		st.Fails = 0
	}
	return st
}

func (s lockState) marshal() ([]byte, error) {
	return json.Marshal(s)
}
