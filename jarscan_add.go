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

var jarModMarkers = [][]byte{
	[]byte("fabric.mod.json"),
	[]byte("META-INF/mods.toml"),
	[]byte("META-INF/neoforge.mods.toml"),
	[]byte("mcmod.info"),
	[]byte("quilt.mod.json"),
}
var jarRootExecExts = map[string]bool{
	".exe": true, ".scr": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".vbe": true, ".jse": true,
	".com": true, ".msi": true,
}
var jarNativeLibExts = map[string]bool{
	".dll": true, ".so": true, ".dylib": true,
}

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
