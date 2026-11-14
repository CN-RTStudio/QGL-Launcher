package main

import (
	"crypto/md5"
	"fmt"

)

func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := md5.Sum([]byte(data))

	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// generateRandomToken 生成随机访问令牌（避免Demo模式）
