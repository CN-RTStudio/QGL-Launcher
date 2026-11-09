package main

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
	"-noverify":                      "noverify",
	"-xverify:none":                  "noverify",
	"-xverify=none":                  "noverify",
	"-xx:+enabledynamicagentloading": "dynamic-agent",
}
