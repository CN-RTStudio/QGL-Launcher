package main

import (
	"strings"

)

func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	// 将参数分组：每个以 - 开头的参数 + 它的后续值为一个组
	type argGroup struct {
		fullKey string // 键 + 所有值的拼接（用于去重判断）
		parts   []string // 原始参数列表
	}
	var groups []argGroup
	current := argGroup{}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if current.fullKey != "" {
				groups = append(groups, current)
			}
			current = argGroup{fullKey: arg, parts: []string{arg}}
		} else {
			current.fullKey = current.fullKey + "\x00" + arg // 用 NULL 分隔键和值
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}

	// 按 fullKey 去重（相同键+相同值才去重，不同值的同名参数保留）
	seen := make(map[string]bool)
	var result []string
	for _, g := range groups {
		if !seen[g.fullKey] {
			seen[g.fullKey] = true
			result = append(result, g.parts...)
		}
	}

	return result
}

// watchGameProcess 监控游戏进程（参考PCL的Watcher类）
// 同时检测：窗口出现、进程退出、崩溃日志、加载进度
