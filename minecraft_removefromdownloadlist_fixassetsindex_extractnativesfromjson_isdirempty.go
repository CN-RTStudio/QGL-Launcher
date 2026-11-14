package main

import (
	"os"

)

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

// setGameLanguage 设置游戏语言为中文（参考 PCL 的 options.txt 修改逻辑）
// 修改游戏目录下的 options.txt 中的 lang 字段
// MC 版本语言格式：
//   1.1~1.5: zh_CN（最后两位必须大写，否则崩溃）
//   1.6~1.10: zh_CN（zh_cn 会自动切换为英文）
//   1.11~1.12: zh_cn（zh_CN 虽然显示中文但语言设置会错误显示英文）
//   1.13+: zh_cn（zh_CN 会自动切换为英文）
