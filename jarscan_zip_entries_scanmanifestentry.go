package main

import (
	"archive/zip"
	"fmt"
	"path"
	"strings"
)

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
