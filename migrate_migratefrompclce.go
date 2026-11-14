package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

)

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
