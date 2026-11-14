package main

import (
	"sync"
	"time"
)

// JavaEntry 表示一个已安装的 Java 运行时
type JavaEntry struct {
	Path     string `json:"path"`     // javaw.exe 完整路径
	Version  string `json:"version"`  // 版本号字符串，如 "1.8.0_321"
	MajorVer int    `json:"majorVer"` // 主版本号，如 8, 17, 21
	Is64Bit  bool   `json:"is64Bit"`  // 是否64位
	IsJDK    bool   `json:"isJDK"`    // 是否JDK
}

// JavaVersionReq 表示 MC 版本对 Java 的版本需求
type JavaVersionReq struct {
	MinMajor int // 最低主版本号
	MaxMajor int // 最高主版本号（0表示无上限）
}

// SearchJava 搜索系统中所有已安装的 Java。
// 全盘扫描（A-Z 盘 + AppData 递归）很慢，而一次启动流程里选 Java、安装器
// 选 Java、兼容检查会反复调用。对结果做短时缓存，TTL 内直接返回快照，
// 避免每次都把所有磁盘遍历一遍造成明显卡顿。
var (
	javaSearchMu    sync.Mutex
	javaSearchCache []JavaEntry
	javaSearchAt    time.Time
)

// javaSearchTTL 内复用上次全盘扫描结果；用户新装 JDK 后重新搜索最坏等待 TTL。
const javaSearchTTL = 2 * time.Minute

func (a *App) SearchJava() []JavaEntry {
	javaSearchMu.Lock()
	if javaSearchCache != nil && time.Since(javaSearchAt) < javaSearchTTL {
		cached := append([]JavaEntry(nil), javaSearchCache...)
		javaSearchMu.Unlock()
		return cached
	}
	javaSearchMu.Unlock()

	results := a.scanJavaInstallations()

	javaSearchMu.Lock()
	javaSearchCache = append([]JavaEntry(nil), results...)
	javaSearchAt = time.Now()
	javaSearchMu.Unlock()
	return results
}

// scanJavaInstallations 执行实际的全盘 Java 扫描，SearchJava 的 TTL 缓存包在外面。
