package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// secureMrpackDestRel 校验并返回可安全拼接到实例目录的 '/'-相对路径。
func secureMrpackDestRel(raw string) (string, string) {
	clean, why := cleanMrpackPathSegments(raw)
	if why != mrpRejectNone {
		return "", why
	}
	if why := mrpackPathPolicy(clean); why != mrpRejectNone {
		return "", why
	}
	return clean, mrpRejectNone
}

// secureMrpackDest 把相对路径安全拼接到实例根目录，并做落盘前的“必须在根内”第二道复核。
func secureMrpackDest(baseDir, raw string) (string, error) {
	rel, why := secureMrpackDestRel(raw)
	if why != mrpRejectNone {
		return "", fmt.Errorf("%s: %s", describeMrpackReject(why), raw)
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !PathWithinRoot(dest, baseDir) {
		return "", fmt.Errorf("整合包文件解析后越出实例目录: %s", raw)
	}
	return dest, nil
}

// validateMrpackHash 校验单个文件的哈希表：键只能是 sha1/sha512，值必须是对应长度的
// 合法十六进制，且至少提供一个。返回错误原因码。
func validateMrpackHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return mrpRejectNoHash
	}
	for alg, val := range hashes {
		var wantLen int
		switch alg {
		case "sha1":
			wantLen = 40
		case "sha512":
			wantLen = 128
		default:
			return mrpRejectBadHashAlg
		}
		v := strings.TrimSpace(val)
		if len(v) != wantLen {
			return mrpRejectBadHashValue
		}
		if _, err := hex.DecodeString(v); err != nil {
			return mrpRejectBadHashValue
		}
	}
	if _, ok := hashes["sha1"]; !ok {
		if _, ok512 := hashes["sha512"]; !ok512 {
			return mrpRejectNoHash
		}
	}
	return mrpRejectNone
}
