package main

import (
	"crypto/rand"
	"encoding/hex"

)

func randomDirName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadUserRegistry 读取用户注册表；若不存在 user.json 且有旧版用户文件夹则自动迁移转换
