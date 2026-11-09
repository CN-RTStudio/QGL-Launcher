package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

// scanNestedJar 在有界深度 / 数量 / 字节预算内递归扫描一个嵌套 jar，
// 直接把内部条目收集进同一个总报告，critical 会正常向上传播触发阻断。
func scanNestedJar(rep *JarScanReport, f *zip.File, display string, depth int,
	nestedCount *int, nestedBytes *int) {
	if depth >= jarScanMaxNestedDepth {
		rep.nestedLimitDepth = true
		return
	}
	if *nestedCount >= jarScanMaxNestedJars || *nestedBytes >= jarScanNestedBytesCap {
		rep.nestedLimitCount = true
		return
	}

	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	left := jarScanNestedBytesCap - *nestedBytes
	limit := int64(jarScanPerNestedCap)
	if int64(left) < limit {
		limit = int64(left)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return
	}
	childZr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// 嵌套条目不是合法 zip：可能损坏或伪装，记 warn 但不因此误杀整个 Mod。
		rep.add(JarSeverityWarn, "nested-unreadable", display,
			"内嵌 .jar 条目无法解析，可能损坏或被刻意伪装，其内容未纳入校验")
		return
	}

	*nestedCount++
	*nestedBytes += len(data)
	scanZipInto(rep, childZr, depth+1, display+"!/", nestedCount, nestedBytes)
}

// scanManifestEntry 读取并解析 MANIFEST.MF 的关键头（处理 CRLF 与续行折叠）。
func scanManifestEntry(rep *JarScanReport, f *zip.File, entryName string) {
	heads := readManifestHeaders(f)
	if heads == nil {
		return
	}
	for _, key := range jarAgentManifestKeys {
		if v := heads[key]; v != "" {
			sev := JarSeverityWarn
			rep.add(sev, "jvm-agent-manifest", entryName,
				fmt.Sprintf("MANIFEST 声明 %s=%s，具备 JVM 代理/注入自启动入口", key, v))
		}
	}
	if heads["Main-Class"] != "" {
		rep.add(JarSeverityInfo, "main-class", entryName,
			"MANIFEST 含 Main-Class="+heads["Main-Class"]+"，该 jar 可被当作可执行程序直接运行")
	}
}

// scanServiceEntry 只看少数与早期类加载挂钩相关的服务契约。
func scanServiceEntry(rep *JarScanReport, f *zip.File, entryName string) {
	base := strings.ToLower(path.Base(f.Name))
	switch base {
	case "cpw.mods.modlauncher.itransformationservice",
		"cpw.mods.modlauncher.ilaunchhandlerservice",
		"cpw.mods.bootstraplauncher.ibootstraplistener",
		"net.minecraftforge.forgespi.locating.imodlocator":
		rep.add(JarSeverityWarn, "classloader-transform-service", entryName,
			"声明类加载转换/启动服务，会早于 Mod 生命周期执行，属高权限挂钩点")
	}
}

// readManifestHeaders 读取 MANIFEST（有上限），折叠续行，返回大写键映射。
func readManifestHeaders(f *zip.File) map[string]string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	limited := io.LimitReader(rc, jarScanTextCap)
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), jarScanTextCap)

	heads := map[string]string{}
	var curKey, curVal string
	flush := func() {
		if curKey != "" {
			heads[strings.ToUpper(curKey)] = strings.TrimSpace(curVal)
		}
		curKey, curVal = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// MANIFEST 续行：以空格或制表符开头的行拼接到上一个值。
		if line[0] == ' ' || line[0] == '\t' {
			curVal += strings.TrimLeft(line, " \t")
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		curKey = line[:colon]
		curVal = strings.TrimSpace(line[colon+1:])
	}
	flush()
	return heads
}

// isJarRootEntry 判断条目是否位于 jar 根目录（不含目录分隔符）。
func isJarRootEntry(lowerName string) bool {
	return !strings.Contains(lowerName, "/")
}

// pathExtLower 返回小写扩展名（含点），无扩展名返回空串。
func pathExtLower(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 || strings.LastIndexByte(name, '/') > dot {
		return ""
	}
	return name[dot:]
}

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
