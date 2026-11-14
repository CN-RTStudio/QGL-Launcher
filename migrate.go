package main

import (
	"os"
	"path/filepath"

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
