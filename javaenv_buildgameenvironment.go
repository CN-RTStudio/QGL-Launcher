package main

import (
	"strings"
)

func buildGameEnvironment(parent []string, extra map[string]string, stripped *[]string) []string {
	return buildGameEnvironmentAudited(parent, extra, stripped, nil)
}

// buildGameEnvironmentAudited 在 buildGameEnvironment 基础上额外收集“因键 / 值
// 非法（NUL、控制字符、空白填充、超长等）而被拒绝”的条目，供启动入口记日志与
// 安全审计。rejected 传 nil 时行为与 buildGameEnvironment 完全一致。
func buildGameEnvironmentAudited(parent []string, extra map[string]string, stripped *[]string, rejected *[]envRejection) []string {
	index := make(map[string]int) // 归一化大写名 -> env 切片下标
	env := make([]string, 0, len(parent)+len(extra))

	// 先清洗继承环境：丢弃缺 '='、空键、键 / 值含 NUL 的脏条目，避免它们破坏
	// CreateProcess 的 NUL 分隔环境块。
	cleanParent, dropped := sanitizeInheritedEnv(parent)
	if rejected != nil {
		*rejected = append(*rejected, dropped...)
	}

	for _, entry := range cleanParent {
		key, value, _ := splitEnvironEntry(entry)
		if isJVMInjectionEnv(key) {
			if stripped != nil {
				*stripped = append(*stripped, strings.ToUpper(strings.TrimSpace(key)))
			}
			continue
		}
		upper := strings.ToUpper(key)
		if pos, exists := index[upper]; exists {
			env[pos] = key + "=" + value
			continue
		}
		index[upper] = len(env)
		env = append(env, key+"="+value)
	}

	// extra 是启动器自己拼的输入，口径更严格：键首尾空白、'='、NUL / 控制字符、
	// 超长一律拒绝，值同样不允许 NUL / 控制字符 / 超长。
	accepted, extraRejected := acceptExtraEnv(extra)
	if rejected != nil {
		*rejected = append(*rejected, extraRejected...)
	}

	for key, value := range accepted {
		upper := strings.ToUpper(key)
		if pos, exists := index[upper]; exists {
			env[pos] = key + "=" + value
			continue
		}
		index[upper] = len(env)
		env = append(env, key+"="+value)
	}

	return env
}

// currentGameEnvironment 是实际启动游戏时调用的便捷封装：读取当前进程环境，
// 剥掉 JVM 注入变量，返回可直接赋给 cmd.Env 的列表与被剥掉的变量名。
