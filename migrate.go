package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

)

// ===== PCL / PCL CE 数据迁移 =====

// MigrateUserResult 用户迁移结果
type MigrateUserResult struct {
	Imported int      `json:"imported"` // 成功导入的离线用户数
	Skipped  int      `json:"skipped"`  // 跳过的数量（已存在或无法迁移的正版/外置账号）
	Names    []string `json:"names"`    // 导入的用户名列表
}

// pclCEProfilesPath 获取 PCL CE 的 Profiles.json 路径
func pclCEProfilesPath() string {
	appdata := os.Getenv("APPDATA")
	return filepath.Join(appdata, ".PCLCE", "Profiles.json")
}

// MigrateFromPCLCE 从 PCL CE 迁移用户数据
// 读取 %APPDATA%\.PCLCE\Profiles.json，导入所有离线档案（明文）
// 正版/外置档案的令牌是本机硬件加密的，无法迁移，只能统计数量提示用户重新登录
func (a *App) MigrateFromPCLCE() (MigrateUserResult, error) {
	result := MigrateUserResult{Names: []string{}}

	data, err := os.ReadFile(pclCEProfilesPath())
	if err != nil {
		return result, fmt.Errorf("未找到 PCL CE 的档案文件（Profiles.json），请确认已安装 PCL CE")
	}

	var profiles struct {
		LastUsed int `json:"lastUsed"`
		Profiles []struct {
			Type     string `json:"type"`
			Username string `json:"username"`
			Desc     string `json:"desc"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(data, &profiles); err != nil {
		return result, fmt.Errorf("解析 PCL CE 档案文件失败: %w", err)
	}

	for _, p := range profiles.Profiles {
		username := strings.TrimSpace(p.Username)
		if username == "" {
			continue
		}
		// 只迁移离线档案；type 为空时也按离线处理
		if p.Type != "" && p.Type != "offline" {
			result.Skipped++
			continue
		}
		// 已存在同名同类型用户则跳过（随机文件夹机制下按注册表判断）
		if a.findUserByNameAndType(username, UserTypeOffline) != nil {
			result.Skipped++
			continue
		}
		// 创建离线用户（不设密码，文件夹名为随机字符串）
		dir, err := a.CreateUser(username, "")
		if err != nil {
			result.Skipped++
			continue
		}
		if err := a.saveUserType(dir, UserTypeOffline); err != nil {
			result.Skipped++
			continue
		}
		// PCL 默认开启版本隔离，迁移的用户保持一致
		if err := a.SaveUserConfig(dir, &UserConfig{VersionIsolation: true}); err != nil {
			result.Skipped++
			continue
		}
		result.Imported++
		result.Names = append(result.Names, username)
	}

	return result, nil
}

// SelectPclExe 弹出文件选择框选择 PCL 的可执行文件（PCL.exe / PCLCE.exe）
