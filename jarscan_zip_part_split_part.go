package main

// jarBehaviorPattern 描述一条字节码行为启发式：常量池文本同时包含
// require 与 andAlso（andAlso 为空时只要求 require）即命中。
// 这是“值得人工注意”的能力信号，不直接证明恶意，因此最高只到 warn。
type jarBehaviorPattern struct {
	rule    string
	sev     JarFindingSeverity
	require string
	andAlso string
	detail  string
}

var jarBehaviorPatterns = []jarBehaviorPattern{
	{
		rule:    "behavior-process-exec",
		sev:     JarSeverityWarn,
		require: "java/lang/Runtime",
		andAlso: "exec",
		detail:  "class 常量池引用 Runtime.exec，具备直接拉起外部进程的能力",
	},
	{
		rule:    "behavior-process-builder",
		sev:     JarSeverityWarn,
		require: "java/lang/ProcessBuilder",
		andAlso: "",
		detail:  "class 常量池引用 ProcessBuilder，具备组装并启动系统命令的能力",
	},
	{
		rule:    "behavior-url-classloader",
		sev:     JarSeverityWarn,
		require: "java/net/URLClassLoader",
		andAlso: "",
		detail:  "class 常量池引用 URLClassLoader，可从远端地址动态加载字节码",
	},
	{
		rule:    "behavior-define-class",
		sev:     JarSeverityWarn,
		require: "defineClass",
		andAlso: "",
		detail:  "class 常量池引用 defineClass，可在运行时把内存字节定义为可执行类",
	},
	{
		rule:    "behavior-script-engine",
		sev:     JarSeverityInfo,
		require: "javax/script/",
		andAlso: "",
		detail:  "class 常量池引用脚本引擎（javax.script），具备运行期执行脚本的能力",
	},
	{
		rule:    "behavior-reflective-open",
		sev:     JarSeverityInfo,
		require: "java/lang/reflect/",
		andAlso: "setAccessible",
		detail:  "class 常量池出现反射 + setAccessible，可绕过访问检查触碰内部 API",
	},
}
