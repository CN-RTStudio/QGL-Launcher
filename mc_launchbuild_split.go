package main

import (
	"strings"
	"unicode"
)

// sanitizeLaunchUsername 清洗进入游戏命令行参数的用户名。
// 老版本 version JSON 的 MinecraftArgs 是按空格切分的字符串，
// 用户名里只要含空格/制表符/控制字符，就能在 ${auth_player_name} 处
// 注入任意额外游戏参数（参数注入）。这里剔除空白与控制字符、按 16 个
// rune 截断（Minecraft 用户名上限），清洗后为空则回退 Player。
// 正版用户名本身只会含字母数字下划线，此清洗不影响正常用户。
func sanitizeLaunchUsername(raw string) string {
	var b strings.Builder
	count := 0
	for _, r := range raw {
		if count >= 16 {
			break
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	name := b.String()
	if name == "" {
		return "Player"
	}
	return name
}
