package main

import (
	"archive/zip"
	"bytes"
	"fmt"
)

func (r *JarScanReport) add(sev JarFindingSeverity, rule, entry, detail string) {
	r.Findings = append(r.Findings, JarFinding{
		Rule:     rule,
		Severity: sev,
		Entry:    entry,
		Detail:   detail,
	})
}

// 已知的 Mod 存在性标记：命中任一即认为“它确实声明自己是个 Mod”。
var jarModMarkers = [][]byte{
	[]byte("fabric.mod.json"),
	[]byte("META-INF/mods.toml"),
	[]byte("META-INF/neoforge.mods.toml"),
	[]byte("mcmod.info"),
	[]byte("quilt.mod.json"),
}

// 根目录出现这些扩展名 = 随 jar 携带可直接运行的程序 / 脚本，critical。
var jarRootExecExts = map[string]bool{
	".exe": true, ".scr": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".vbe": true, ".jse": true,
	".com": true, ".msi": true,
}

// 任意位置出现这些扩展名 = 平台本地库，常见于带原生绑定的正常 Mod，仅 info。
var jarNativeLibExts = map[string]bool{
	".dll": true, ".so": true, ".dylib": true,
}

// 这些 MANIFEST 头声明 JVM 代理 / 自启动入口。
var jarAgentManifestKeys = []string{
	"Premain-Class",
	"Agent-Class",
	"Launcher-Agent-Class",
	"LoopLoader-Class",
}

// scanJarBytes 对内存中的 jar 字节做静态扫描（便于测试直接构造 zip）。
func scanJarBytes(data []byte) (*JarScanReport, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 jar/zip 文件: %v", err)
	}
	return scanZipReader(zr), nil
}

// scanJarAt 扫描磁盘上已下载完成的 jar；只读、不执行、不解压。
func scanJarAt(jarPath string) (*JarScanReport, error) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, fmt.Errorf("打开 jar 失败: %v", err)
	}
	defer zr.Close()
	return scanZipReader(&zr.Reader), nil
}

func scanZipReader(zr *zip.Reader) *JarScanReport {
	rep := &JarScanReport{Findings: []JarFinding{}, ruleSeen: map[string]bool{}}
	nestedCount, nestedBytes := 0, 0
	scanZipInto(rep, zr, 1, "", &nestedCount, &nestedBytes)
	rep.finalize()
	return rep
}

// scanZipInto 把一个 zip 层级的条目收集进 rep。depth=1 为最外层 jar；prefix 是
// 嵌套 jar 的路径前缀（外层为空），nestedCount/nestedBytes 是跨层级共享的预算。
