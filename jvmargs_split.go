package main

import (
	"strings"
)

// jvmArgThreat 判定单个 JVM 参数是否危险。
// 入参 lower 必须已是 strings.ToLower(strings.TrimSpace(arg))。
// 返回：
//
//	dangerous       是否应从不可信参数中剔除；
//	consumesOperand 为 true 时，紧跟其后的那一条参数是它的操作数，也要丢弃。
//
// 该函数对所有“关闭校验 / 加载任意字节码 / 替选 JVM / 指定错误时执行命令”
// 的写法 fail-closed；拿不准的普通性能 / 内存参数一律放行，避免误伤官方
// 与主流加载器的正常参数。
func jvmArgThreat(lower string) (dangerous bool, consumesOperand bool) {
	if lower == "" {
		return false, false
	}

	// 1) 响应文件：@ 开头即危险。JVM 不接受 @ 与路径之间有空格
	//    （“@ C:\a”会被当成普通主类名），因此只拦“同一 token 内紧跟路径”。
	//    即便路径为空（裸 "@"）也按危险处理，拒绝任何不可信的参数文件展开。
	if strings.HasPrefix(lower, "@") {
		return true, false
	}

	// 2) 精确开关。
	if reason, ok := jvmExactThreats[lower]; ok {
		_ = reason
		return true, false
	}

	// 3) 前缀类（flag / flag:operand / flag=operand，以及裸 flag）。
	for _, t := range jvmPrefixThreats {
		if lower == t.flag {
			return true, t.operand
		}
		if strings.HasPrefix(lower, t.flag+":") || strings.HasPrefix(lower, t.flag+"=") {
			return true, false
		}
	}

	// 4) 危险 -D 系统属性（换信任库 / 覆盖安全属性 / JMX / 任意类加载等）。
	//    权威判定在 jvmprops.go；普通业务属性（-Dfabric.* / -Djna.tmpdir 等）放行。
	if jvmPropArgThreat(lower) {
		return true, false
	}

	return false, false
}

// classifyUntrustedJvmArg 是 jvmArgThreat 的带原因版本，供安全审计 / 日志使用，
// 对普通参数返回空原因。过滤热路径用 jvmArgThreat 即可，无需分配 reason。
func classifyUntrustedJvmArg(lower string) (reason string, dangerous, consumesOperand bool) {
	if strings.HasPrefix(lower, "@") {
		return "argument-file", true, false
	}
	if r, ok := jvmExactThreats[lower]; ok {
		return r, true, false
	}
	for _, t := range jvmPrefixThreats {
		if lower == t.flag {
			return t.reason, true, t.operand
		}
		if strings.HasPrefix(lower, t.flag+":") || strings.HasPrefix(lower, t.flag+"=") {
			return t.reason, true, false
		}
	}
	if name, value, isProp := parseSystemPropertyArg(lower); isProp {
		if reason, bad := jvmSystemPropertyThreat(name, value); bad {
			return reason, true, false
		}
	}
	return "", false, false
}
