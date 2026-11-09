package main

import (
	"archive/zip"
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
