package main

import "strings"

// jvmargs.go —— 不可信 JVM 启动参数的权威威胁分类器。
//
// 背景：Minecraft 的版本 / 加载器 JSON（fabric / forge / 第三方整合包）里
// 带 JVM 参数，这些参数来自网络、不是用户亲手写的。历史上这里只拦了
// -javaagent / -jar 等十几个“前缀”，但 JVM 还支持若干等价的代码执行 /
// 关闭安全机制的写法，黑名单漏掉任何一个都等于整条 -javaagent 防线失效：
//
//   - @path（argument file / 响应文件）：java 会在极早期把该文件逐行展开成
//     额外命令行参数。恶意 JSON 只要给一个 “@C:\Users\x\a.txt”，文件里写
//     什么 -javaagent 都能注入，完全绕过字符串黑名单。这是本轮的主漏洞。
//   - -noverify / -Xverify:none：关闭字节码校验，让篡改过的 class 直接跑。
//   - -XX:+EnableDynamicAgentLoading：显式允许运行期动态附加 agent，
//     等于把 JDK 21 对“运行中被 attach 注入”的警告闸门手动拆掉。
//   - --source <ver> <File.java>：单文件源码启动，可直接执行落地的源码。
//
// 本文件不依赖 Electron / Wails，纯函数，便于表驱动单测。

// jvmPrefixThreat 描述一个“flag:operand / flag=operand / flag operand”形态的
// 危险前缀。operand 为 true 表示该 flag 允许以“独立 token + 下一条参数”为
// 操作数（如 “-jar evil.jar”），过滤时要把下一条参数一并丢弃。
type jvmPrefixThreat struct {
	flag    string
	reason  string
	operand bool
}

// 前缀匹配时一律比较 lower == flag、lower 以 "flag:" 或 "flag=" 开头。
// 顺序无关；保持与历史黑名单一致并补齐新发现的绕过项。
var jvmPrefixThreats = []jvmPrefixThreat{
	{"-javaagent", "javaagent", true},
	{"-agentlib", "agentlib", true},
	{"-agentpath", "agentpath", true},
	{"-xx:onerror", "onerror", false},
	{"-xx:onoutofmemoryerror", "onoutofmemoryerror", false},
	{"-xx:vmoptionsfile", "vmoptionsfile", false},
	{"-xxaltjvm", "altjvm", false},
	{"-xxaltjvms", "altjvm", false},
	{"-xrun", "xrun", false},
	{"-jar", "main-entry", true},
	{"-m", "main-entry", true},
	{"--module", "main-entry", true},
	{"--source", "source-launch", true},
}

// jvmExactThreats 是“只认精确形式、不接冒号/等号”的危险开关。
// key 已小写；value 为审计 / 日志用的原因码（ASCII，避免编码问题）。
var jvmExactThreats = map[string]string{
	"-noverify":                   "noverify",
	"-xverify:none":               "noverify",
	"-xverify=none":               "noverify",
	"-xx:+enabledynamicagentloading": "dynamic-agent",
}

// jvmArgThreat 判定单个 JVM 参数是否危险。
// 入参 lower 必须已是 strings.ToLower(strings.TrimSpace(arg))。
// 返回：
//   dangerous       是否应从不可信参数中剔除；
//   consumesOperand 为 true 时，紧跟其后的那一条参数是它的操作数，也要丢弃。
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
