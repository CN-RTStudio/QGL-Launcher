package main

import (
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
