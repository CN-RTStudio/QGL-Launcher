package main

import (
	"strings"
)

// jvmprops.go —— 不可信 -D 系统属性（system property）的威胁分类器。
//
// 背景：r22 的 jvmArgThreat 只拦 -javaagent / -jar / @argfile 等“显式 flag”，
// 但外部版本 / 加载器 JSON 里的 -Dkey=value 是整段放行的。HotSpot 在极早期就会
// 读取部分系统属性，其中不少等价于“加载任意字节码 / 关掉安全机制 / 换信任库”，
// 不需要 -javaagent 也能把前面整条参数黑名单绕过去，例如：
//
//   - -Djava.security.properties=https://evil/p
//       追加（=）或整体覆盖（==）JDK 安全属性文件，可禁用证书校验算法、放开
//       TLS 限制、改 codeSigning 策略。
//   - -Djava.security.manager=Evval、-Djava.system.class.loader=EvLoader
//       指定自定义安全管理器 / 系统类加载器类名，启动期即加载攻击者可控的类。
//   - -Djavax.net.ssl.trustStore=... / trustStorePassword / trustStoreType
//       把根信任库换成攻击者的，HTTPS 校验形同虚设（中间人）。keyStore 一族
//       则会把客户端身份证书交给对方。
//   - -Dcom.sun.management.jmxremote.port=...（再配合 .ssl=false /
//       .authenticate=false）开放无认证 JMX/RMI，等价于远程代码执行。
//   - -Djava.rmi.server.codebase=http://evil/ 让 RMI 从远程地址加载类。
//   - -Djava.util.logging.config.class=Ev、-Djava.naming.factory.initial=Ev、
//       -Djava.protocol.handler.pkgs=...、-Dlog4j.configurationFactory=Ev
//       均会在初始化阶段按类名实例化 / 加载任意类。
//   - -Djava.ext.dirs / -Djava.endorsed.dirs 指向放有恶意 jar / class 的目录，
//       扩展类加载器会抢先加载，可覆盖 JDK 自身的类。
//   - -Djdk.attach.allowAttachSelf=true 允许进程自我 attach，等价于放开
//       运行期 javaagent 注入门槛。
//   - -Dlog4j.configurationFile=http(s)://.../file:... 从远程 URL 或外部 file:
//       位置装载 log4j2 配置（本地文件系统路径的正常用法仍保留）。
//
// 与 jvmargs.go 一样，本文件纯函数、表驱动、不依赖 Wails，便于单测。

// jvmPropThreat 描述一个“精确匹配属性名”的危险项。
type jvmPropThreat struct {
	name   string // 已小写的属性名
	reason string
}

// 精确匹配的危险属性名。键值无关：即便用户把开关写成 false，也不允许不可信 JSON
// 去触碰这些安全敏感属性（fail-closed，避免“看起来关闭实则依赖字符串解析”）。
var jvmExactPropThreats = map[string]string{
	// 安全策略 / 类加载骨架
	"java.security.properties":   "sec-properties",
	"java.security.manager":      "sec-manager",
	"java.system.class.loader":   "system-class-loader",
	"java.ext.dirs":              "ext-dirs",
	"java.endorsed.dirs":         "endorsed-dirs",
	"java.protocol.handler.pkgs": "url-handler-pkgs",
	// 日志 / JNDI 任意类加载
	"java.util.logging.config.class": "logging-config-class",
	"java.naming.factory.initial":    "jndi-factory",
	"log4j.configurationfactory":     "log4j-factory",
	"log4j2.configurationfactory":    "log4j-factory",
	// 自我 attach
	"jdk.attach.allowattachself": "attach-self",
	// TLS 信任库 / 身份库
	"javax.net.ssl.truststore":         "truststore",
	"javax.net.ssl.truststorepassword": "truststore",
	"javax.net.ssl.truststoretype":     "truststore",
	"javax.net.ssl.truststoreprovider": "truststore",
	"javax.net.ssl.keystore":           "keystore",
	"javax.net.ssl.keystorepassword":   "keystore",
	"javax.net.ssl.keystoretype":       "keystore",
	"javax.net.ssl.keystoreprovider":   "keystore",
}

// jvmPrefixPropThreat 描述一族“同前缀”危险属性（键值已小写）。
// 命中 name == prefix 或以 prefix+"." 开头即判危险。
var jvmPrefixPropThreats = []jvmPropThreat{
	// com.sun.management.jmxremote / .port / .ssl / .authenticate /
	// .access.file / .password.file / .registry.ssl ...
	{"com.sun.management.jmxremote", "jmxremote"},
	// java.rmi.server.codebase 等远程类加载相关项。
	{"java.rmi.server.codebase", "rmi-codebase"},
}

// parseSystemPropertyArg 解析形如 "-Dname=value" 的参数。
// 入参 arg 必须已是 strings.ToLower(strings.TrimSpace(...))。
// 返回 isProp=true 时 name 为小写属性名、value 为首个 '=' 之后的原始（小写）值。
// "-D" 后面没有名字（裸 "-d" / "-d32" 这类以数字开头的历史开关）不算系统属性。
func parseSystemPropertyArg(lower string) (name, value string, isProp bool) {
	if !strings.HasPrefix(lower, "-d") || len(lower) <= 2 {
		return "", "", false
	}
	body := lower[2:]
	if body == "" {
		return "", "", false
	}
	// 属性名首字符必须是字母，排除 -d32 / -d64 / -dsa 这类历史 JVM 开关被误判。
	first := body[0]
	if !(first >= 'a' && first <= 'z') {
		return "", "", false
	}
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		return strings.TrimSpace(body[:eq]), body[eq+1:], true
	}
	return strings.TrimSpace(body), "", true
}
