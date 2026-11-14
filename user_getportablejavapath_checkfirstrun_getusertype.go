package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) GetUserType(id string) UserType {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Type
	}
	return a.readLegacyUserType(a.userDirFor(id))
}

// saveUserType 保存用户类型（参数为用户标识 dir，同步更新注册表）
func (a *App) saveUserType(id string, userType UserType) error {
	userDir := a.userDirFor(id)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return err
	}
	typeData := struct {
		Type UserType `json:"type"`
	}{Type: userType}
	data, err := json.MarshalIndent(typeData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(userDir, "type.json"), data, 0644); err != nil {
		return err
	}
	// 同步注册表
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			entries[i].Type = userType
			break
		}
	}
	return a.saveUserRegistry(entries)
}
