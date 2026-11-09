package main

type jvmPropThreat struct {
	name   string // 已小写的属性名
	reason string
}

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
