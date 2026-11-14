package main

import (
	"crypto/md5"
	"fmt"
	"os"

)

func (a *App) DeleteCurrentUser(password string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}

	existingMD5 := a.getUserPasswordMD5(currentUser.Dir)
	if existingMD5 != "" {
		if password == "" {
			return fmt.Errorf("该用户已设置密码，请输入密码")
		}
		hash := md5.Sum([]byte(password))
		if fmt.Sprintf("%x", hash) != existingMD5 {
			return fmt.Errorf("密码错误")
		}
	}

	// 清除全局当前用户，避免残留指向已删除的用户
	config, err := a.GetGlobalConfig()
	if err == nil {
		config.CurrentUser = ""
		a.SaveGlobalConfig(config)
	}

	// 从注册表移除该用户
	entries := a.loadUserRegistry()
	filtered := entries[:0]
	for _, e := range entries {
		if e.Dir != currentUser.Dir {
			filtered = append(filtered, e)
		}
	}
	a.saveUserRegistry(filtered)

	userDir := a.userDirFor(currentUser.Dir)
	if err := os.RemoveAll(userDir); err != nil {
		return fmt.Errorf("删除用户目录失败: %w", err)
	}

	a.writeLog("用户 %s 已删除", currentUser.Username)
	return nil
}

// ===== 访客权限管理（保存到访客用户目录的 guest.json）=====

// GuestPermissions 访客权限：控制访客锁定时可以使用哪些功能
// 注意：解锁状态下所有功能均可用，权限仅影响锁定状态
type GuestPermissions struct {
	AllowDownload bool `json:"allowDownload"` // 下载游戏
	AllowMod      bool `json:"allowMod"`      // MOD 管理
	AllowEasyQGL  bool `json:"allowEasyQGL"`  // Easy QGL
	AllowSettings bool `json:"allowSettings"` // 设置
	AllowQGLPlus  bool `json:"allowQGLPlus"`  // QGL+（一键开服/联机）
	AllowHelper   bool `json:"allowHelper"`   // 辅助模式
}

// DefaultGuestPermissions 默认访客权限（全部允许）
