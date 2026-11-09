package main

import (
	"archive/zip"
	"path/filepath"
)

// Forge/NeoForge 安装器是从镜像下载的不受信任 JAR，其中 maven/ 条目会被
// 解压到 libraries。统一走 zipextract 安全解压内核：Zip Slip、符号链接等特殊
// 条目、条目数 / 单条目 / 总量上限全部预检，落盘采用临时文件 + 原子替换。
// 正常的依赖 jar 只有几 MB 到几十 MB，正常数据永远碰不到这些阈值。
const (
	maxMavenEntryBytes int64 = 256 << 20 // 单个 maven 条目 256 MiB
	maxMavenTotalBytes int64 = 2 << 30   // maven 解压总量 2 GiB
	maxMavenEntries          = 100000    // maven 条目数上限（inode 耗尽防护）
)

func (a *App) extractMavenFiles(installerPath string, mcDir string) error {
	r, err := zip.OpenReader(installerPath)
	if err != nil {
		return err
	}
	defer r.Close()

	libsDir := filepath.Join(mcDir, "libraries")
	lim := zipExtractLimits{
		EntryMax:   maxMavenEntryBytes,
		TotalMax:   maxMavenTotalBytes,
		MaxEntries: maxMavenEntries,
	}
	n, count, err := extractZipPrefixes(r.File, libsDir, []string{"maven/"}, lim, a.writeLog)
	if err != nil {
		return err
	}
	a.writeLog("maven 解压完成: %d 个文件，共 %d 字节", count, n)
	return nil
}
