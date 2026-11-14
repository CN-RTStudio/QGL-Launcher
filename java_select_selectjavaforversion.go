package main

import (
	"fmt"
)

func (a *App) SelectJavaForVersion(versionID string) (*JavaEntry, error) {
	req := a.GetJavaRequirement(versionID)
	// 1. 便携版模式：优先使用 QGL\pe\java\bin\java.exe
	config, _ := a.GetGlobalConfig()
	if config != nil && config.PortableMode {
		portableJava := a.GetPortableJavaInfo()
		if portableJava != nil {
			if isJavaCompatible(portableJava, req) {
				return portableJava, nil
			}
			// 便携版 Java 不兼容，继续搜索其他 Java
		}
	}
	// 2. 检查用户手动设置的 Java
	if config != nil && config.JavaPath != "" {
		javaEntry := validateJava(config.JavaPath)
		if javaEntry != nil {
			if isJavaCompatible(javaEntry, req) {
				return javaEntry, nil
			}
			// 手动设置的 Java 不兼容，返回提示
			displayMin := req.MinMajor
			if displayMin <= 0 {
				displayMin = 8
			}
			return nil, fmt.Errorf("手动设置的 Java %s (Java %d) 不适用于 MC %s (需要 Java %d-%s)，请在设置中更换 Java",
				javaEntry.Version, javaEntry.MajorVer, versionID, displayMin, formatMaxVer(req.MaxMajor))
		}
	}
	// 3. 搜索系统中所有 Java
	javaList := a.SearchJava()
	// 4. 过滤出兼容的 Java
	var compatible []JavaEntry
	for _, j := range javaList {
		if isJavaCompatible(&j, req) {
			compatible = append(compatible, j)
		}
	}
	if len(compatible) > 0 {
		return &compatible[0], nil
	}
	// 5. 没有找到兼容的 Java
	displayMin := req.MinMajor
	if displayMin <= 0 {
		displayMin = 8
	}
	if len(javaList) == 0 {
		return nil, fmt.Errorf("未找到任何已安装的 Java，请安装 Java %d 或更高版本", displayMin)
	}
	// 有 Java 但不兼容
	best := javaList[0]
	return nil, fmt.Errorf("未找到适用于 MC %s 的 Java (需要 Java %d-%s)，当前最接近的 Java 为 %s (Java %d)，请安装合适的 Java 版本",
		versionID, displayMin, formatMaxVer(req.MaxMajor), best.Version, best.MajorVer)
}

// isJavaCompatible 检查 Java 是否满足版本需求
