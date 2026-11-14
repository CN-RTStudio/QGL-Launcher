package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
)

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
