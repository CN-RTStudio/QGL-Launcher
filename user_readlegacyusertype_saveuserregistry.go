package main

import (
	"encoding/json"
	"os"

)

func (a *App) saveUserRegistry(entries []UserEntry) error {
	os.MkdirAll(a.GetUsersDir(), 0755)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.userRegistryPath(), data, 0644)
}

// findUserEntry 按标识（dir）查找注册表条目
func (a *App) findUserEntry(id string) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			return &entries[i]
		}
	}
	return nil
}

// userNameByID 按标识（dir）查显示用户名（查不到返回原值，兼容迁移前调用）
