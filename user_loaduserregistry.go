package main

import (
	"encoding/json"
	"os"

)

func (a *App) loadUserRegistry() []UserEntry {
	data, err := os.ReadFile(a.userRegistryPath())
	if err == nil {
		var entries []UserEntry
		if json.Unmarshal(data, &entries) == nil && entries != nil {
			return entries
		}
	}
	// 迁移：旧版以用户名作为文件夹名，转换为随机文件夹名
	return a.migrateUserRegistry()
}

// migrateUserRegistry 旧版用户目录迁移：文件夹名(用户名) -> 随机文件夹名 + user.json 注册表
