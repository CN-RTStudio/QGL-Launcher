package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

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
