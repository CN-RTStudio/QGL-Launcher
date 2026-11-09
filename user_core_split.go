package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

// GlobalConfig 全局配置
type GlobalConfig struct {
	CurrentUser  string `json:"currentUser"`
	JavaPath     string `json:"javaPath"`
	MaxMemory    int    `json:"maxMemory"`
	MinMemory    int    `json:"minMemory"`
	MinecraftDir string `json:"minecraftDir"` // 自定义 .minecraft 目录，留空则使用默认路径
	PortableMode bool   `json:"portableMode"` // 便携版模式：优先使用 QGL\pe\java\bin\java.exe
}

// validateUsername 安全加固: 校验用户名，防止路径遍历
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if len(username) > 64 {
		return fmt.Errorf("用户名过长")
	}
	// 禁止路径遍历字符
	if strings.Contains(username, "..") || strings.Contains(username, "/") || strings.Contains(username, "\\") {
		return fmt.Errorf("用户名包含非法字符")
	}
	// 禁止控制字符
	for _, c := range username {
		if c < 32 || c == 127 {
			return fmt.Errorf("用户名包含控制字符")
		}
	}
	// 账户名最终会拼成 Users/<name>/ 目录段，再走一次统一的落盘名单段内核，
	// 补齐上面旧检查漏掉的 Windows 保留设备名、ADS 冒号与不可见 / 双向覆写 Unicode。
	if _, why := SafeAccountName(username); why != nameRejectNone {
		return fmt.Errorf("用户名未通过安全校验: %s", describeNameReject(why))
	}
	return nil
}

// hashPassword 安全加固: 使用 bcrypt 哈希密码
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPassword 安全加固: 使用 bcrypt 验证密码
