package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) readLegacyUserType(userDir string) UserType {
	data, err := os.ReadFile(filepath.Join(userDir, "type.json"))
	if err != nil {
		return UserTypeOffline
	}
	var typeData struct {
		Type UserType `json:"type"`
	}
	if json.Unmarshal(data, &typeData) != nil {
		return UserTypeOffline
	}
	return typeData.Type
}

// saveUserRegistry 保存用户注册表
