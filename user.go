package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

)

// UserType 用户类型
type UserType string

const (
	UserTypeGuest    UserType = "guest"    // 访客用户
	UserTypeOffline  UserType = "offline"  // 离线用户
	UserTypePremium  UserType = "premium"  // 正版用户
	UserTypeExternal UserType = "external" // 外置用户（Yggdrasil）
)

// UserInfo 用户信息
type UserInfo struct {
	Username    string   `json:"username"`
	Dir         string   `json:"dir"`       // 用户文件夹名（随机字符串，作为用户唯一标识）
	HasPassword bool     `json:"hasPassword"`
	Type        UserType `json:"type"`
	IsLocked    bool     `json:"isLocked"`
	ServerName  string   `json:"serverName"` // 外置用户的服务器名称
	ServerURL   string   `json:"serverUrl"`  // 外置用户的验证服务器地址（令牌过期重新登录时预填）
}

// UserEntry 用户注册表条目（QGL/Users/user.json）
// name 为显示用户名（可重复），dir 为随机文件夹名（唯一标识），
// 这样不同模式的用户即使同名也不会互相覆盖
type UserEntry struct {
	Name string   `json:"name"` // 显示用户名
	Type UserType `json:"type"` // 用户类型
	Dir  string   `json:"dir"`  // 用户文件夹名（随机字符串）
}

// userRegistryPath 用户注册表路径
func (a *App) userRegistryPath() string {
	return filepath.Join(a.GetUsersDir(), "user.json")
}

// randomDirName 生成随机文件夹名（16 位十六进制）
func randomDirName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadUserRegistry 读取用户注册表；若不存在 user.json 且有旧版用户文件夹则自动迁移转换
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
