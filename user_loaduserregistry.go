package main

import (
	"encoding/json"
	"os"
	"path/filepath"

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
func (a *App) migrateUserRegistry() []UserEntry {
	usersDir := a.GetUsersDir()
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return []UserEntry{}
	}

	var result []UserEntry
	migrated := false
	oldCurrent := ""
	if config, err := a.GetGlobalConfig(); err == nil {
		oldCurrent = config.CurrentUser
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		oldName := entry.Name()
		newDir := randomDirName()
		// 文件夹重命名失败（如被占用）则保留原名，同样注册进注册表，不影响使用
		if renameErr := os.Rename(filepath.Join(usersDir, oldName), filepath.Join(usersDir, newDir)); renameErr == nil {
			migrated = true
		} else {
			newDir = oldName
		}
		userType := a.readLegacyUserType(filepath.Join(usersDir, newDir))
		result = append(result, UserEntry{Name: oldName, Type: userType, Dir: newDir})
		// 同步修正全局配置中的当前用户
		if oldCurrent == oldName {
			if config, err := a.GetGlobalConfig(); err == nil {
				config.CurrentUser = newDir
				a.SaveGlobalConfig(config)
			}
		}
	}

	a.saveUserRegistry(result)
	if migrated && len(result) > 0 {
		a.writeLog("用户目录已迁移到随机文件夹名机制（共 %d 个用户）", len(result))
	}
	return result
}

// readLegacyUserType 从用户文件夹的 type.json 读取用户类型（迁移用）
