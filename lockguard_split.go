package main

import (
	"encoding/hex"
	"encoding/json"
)

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
