package main

import (
	"path/filepath"
	"strings"
)

const maxUntrustedJvmArgs = 256

func isDangerousJvmFlag(lower string) bool {
	dangerous, _ := jvmArgThreat(lower)
	return dangerous
}

func filterUntrustedJvmArgs(args []string) (safe []string, blocked []string, truncated bool) {
	skipOperand := false
	for i, arg := range args {
		if skipOperand {
			skipOperand = false
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(arg))
		dangerous, consumesOperand := jvmArgThreat(lower)
		if dangerous {
			blocked = append(blocked, arg)
			// 独立 token 形式时，下一条参数是其操作数（路径/命令），一并跳过。
			if consumesOperand {
				skipOperand = true
			}
			continue
		}
		safe = append(safe, arg)
		if len(safe) >= maxUntrustedJvmArgs {
			truncated = i+1 < len(args)
			break
		}
	}
	return safe, blocked, truncated
}

// expandConditionalArg 展开 arguments 数组里的一个元素，JVM 参数与游戏参数共用同一套逻辑：
// 普通字符串逐占位替换后成 1 条；带 rules 的对象先用 shouldIncludeArg 按当前环境
// 判定，再把其 value（字符串或字符串数组）逐项展开替换；不符合规则 / 取值畸形返回 nil。
// 历史上 resolveJVMArg 与 resolveGameArg 各写一份且都内联手写替换循环，这里收口
// 成一份，避免两份实现再漂移。
func expandConditionalArg(arg interface{}, repl map[string]string) []string {
	apply := func(s string) string {
		for k, v := range repl {
			s = strings.ReplaceAll(s, k, v)
		}
		return s
	}
	switch v := arg.(type) {
	case string:
		return []string{apply(v)}
	case map[string]interface{}:
		if !shouldIncludeArg(v) {
			return nil
		}
		values, ok := v["value"]
		if !ok {
			return nil
		}
		switch val := values.(type) {
		case string:
			return []string{apply(val)}
		case []interface{}:
			var result []string
			for _, item := range val {
				if s, isString := item.(string); isString {
					result = append(result, apply(s))
				}
			}
			return result
		}
	}
	return nil
}

func resolveJVMArg(arg interface{}, nativesDir, mcDir, classpath, versionID string) []string {
	return expandConditionalArg(arg, map[string]string{
		"${natives_directory}":   nativesDir,
		"${library_directory}":   filepath.Join(mcDir, "libraries"),
		"${libraries_directory}": filepath.Join(mcDir, "libraries"),
		"${classpath_separator}": ";",
		"${classpath}":           classpath,
		"${launcher_name}":       "QGL",
		"${launcher_version}":    "1.0.0",
		"${version_name}":        versionID,
	})
}

func resolveGameArg(arg interface{}, repl map[string]string) []string {
	return expandConditionalArg(arg, repl)
}
