package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
)

func scanZipInto(rep *JarScanReport, zr *zip.Reader, depth int, prefix string,
	nestedCount *int, nestedBytes *int) {
	classScanBytes := 0
	limited := false

	for i, f := range zr.File {
		if i >= jarScanMaxEntries {
			limited = true
			break
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if name == "" {
			continue
		}
		rep.Entries++
		lower := strings.ToLower(name)
		ext := pathExtLower(lower)
		display := prefix + name

		switch {
		case ext == ".class":
			rep.ClassFiles++
			if rep.ScannedClasses < jarScanMaxScannedClasses && classScanBytes < jarScanClassBytesCap {
				if n := scanClassBehavior(rep, f, display, classScanBytes); n > 0 {
					classScanBytes += n
					rep.ScannedClasses++
				}
			}
		case jarNativeLibExts[ext]:
			rep.NativeLibs++
			rep.add(JarSeverityInfo, "native-library", display, "jar 携带平台本地库（正常 Mod 可能包含，已记录）")
		case ext == ".jar":
			rep.NestedJars++
			rep.add(JarSeverityInfo, "nested-jar", display, "jar 内嵌 jar（JarJar/依赖遮蔽），已在有界预算内递归扫描其内容")
			scanNestedJar(rep, f, display, depth, nestedCount, nestedBytes)
		case ext == ".pack" || strings.HasSuffix(lower, ".pack.gz") || ext == ".pack200":
			rep.add(JarSeverityWarn, "pack200-carrier", display, "Pack200 载体在类加载时才解包，可藏匿不被静态扫描的类")
		}

		// 根目录可执行程序 / 脚本：在其所属 jar 层级的根目录，critical。
		if isJarRootEntry(lower) && jarRootExecExts[ext] {
			rep.add(JarSeverityCritical, "root-executable", display,
				"jar 根目录携带可直接运行的可执行文件/脚本，属高置信度恶意载荷")
		}

		// Mod 存在性标记（相对路径判定，不受外层前缀影响）。
		for _, marker := range jarModMarkers {
			if bytes.EqualFold([]byte(lower), marker) {
				rep.HasModMarker = true
			}
		}

		// Nashorn coremod 脚本：在 ModLauncher 类加载阶段执行 JS。
		if strings.HasPrefix(lower, "meta-inf/") && ext == ".js" {
			rep.add(JarSeverityWarn, "coremod-script", display,
				"META-INF 内脚本会在类加载阶段以 Nashorn 执行，属高权限早期代码")
		}

		// ModLauncher 转换 / 启动服务：在 Mod 生命周期前挂钩类加载。
		if strings.HasPrefix(lower, "meta-inf/services/") {
			scanServiceEntry(rep, f, display)
		}

		// 多发行版 jar 覆盖 java.* 基础包可影子替换运行时类。
		if strings.HasPrefix(lower, "meta-inf/versions/") {
			if strings.Contains(lower, "/java/") {
				rep.add(JarSeverityWarn, "multi-release-runtime", display,
					"多发行版条目覆盖 java.* 运行时类，可影子替换平台实现")
			}
		}

		if lower == "meta-inf/manifest.mf" {
			scanManifestEntry(rep, f, display)
		}
	}

	if limited {
		rep.limitedEntries = true
	}
}

// finalize 在最外层扫描结束后统一补充上限提示与“无 Mod 标记”结论。
func (r *JarScanReport) finalize() {
	if r.limitedEntries {
		r.add(JarSeverityInfo, "scan-limit-reached", "",
			fmt.Sprintf("条目数超过 %d，仅扫描了前 %d 条", jarScanMaxEntries, r.Entries))
	}
	if r.ClassFiles > r.ScannedClasses {
		r.add(JarSeverityInfo, "class-scan-limit-reached", "",
			fmt.Sprintf("class 条数或总体积超过静态行为分析上限（%d 条 / %d MiB），仅分析了前 %d 个 class",
				jarScanMaxScannedClasses, jarScanClassBytesCap>>20, r.ScannedClasses))
	}
	if r.nestedLimitDepth {
		r.add(JarSeverityInfo, "nested-depth-limit", "",
			fmt.Sprintf("嵌套 jar 深度超过 %d 层，更内层未展开扫描", jarScanMaxNestedDepth))
	}
	if r.nestedLimitCount {
		r.add(JarSeverityInfo, "nested-count-limit", "",
			fmt.Sprintf("嵌套 jar 数量超过 %d 个或总体积超限，部分未展开扫描", jarScanMaxNestedJars))
	}

	// 有 .class 却完全没有任何 Mod 标记：可能是伪装成 Mod 的可执行 jar。
	if r.ClassFiles > 0 && !r.HasModMarker {
		r.add(JarSeverityWarn, "no-mod-marker", "",
			"jar 含编译后的 .class 但没有 fabric.mod.json/mods.toml/mcmod.info 等 Mod 声明，可能并非正常 Mod")
	}
}
