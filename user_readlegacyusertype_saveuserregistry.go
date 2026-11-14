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
