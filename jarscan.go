package main

import (
	"archive/zip"
	"bytes"
	"fmt"
)

const (
	// jarScanMaxEntries 限制单个 jar 参与分析的条目数，防海量条目耗尽 CPU。
	jarScanMaxEntries = 50000
	// jarScanTextCap 限制单个文本条目（MANIFEST/services）最多读取的字节数。
	jarScanTextCap = 1 << 20 // 1 MiB
	// jarScanMaxScannedClasses 限制参与字节码行为分析的 .class 条数。
	jarScanMaxScannedClasses = 2000
	// jarScanPerClassCap 限制单个 class 的读取字节数。
	jarScanPerClassCap = 1 << 20 // 1 MiB
	// jarScanClassBytesCap 限制一次扫描中所有 class 累计读取的字节数，
	// 防止超大 class 或海量 class 拖垮安装流程。
	jarScanClassBytesCap = 16 << 20 // 16 MiB
	// jarScanMaxNestedDepth 是嵌套 jar（JarJar）递归扫描的最大深度：
	// 外层 jar 记为第 1 层，最多向内再扫到第 2 层。
	jarScanMaxNestedDepth = 2
	// jarScanMaxNestedJars 限制一次扫描中参与递归的嵌套 jar 数量，防“jar 套娃”炸弹。
	jarScanMaxNestedJars = 32
	// jarScanNestedBytesCap 限制所有嵌套 jar 累计读取字节数。
	jarScanNestedBytesCap = 64 << 20 // 64 MiB
	// jarScanPerNestedCap 限制单个嵌套 jar 的读取字节数。
	jarScanPerNestedCap = 8 << 20 // 8 MiB
)

type JarFindingSeverity string

const (
	JarSeverityInfo     JarFindingSeverity = "info"
	JarSeverityWarn     JarFindingSeverity = "warn"
	JarSeverityCritical JarFindingSeverity = "critical"
)

type JarFinding struct {
	Rule     string             `json:"rule"`
	Severity JarFindingSeverity `json:"severity"`
	Entry    string             `json:"entry"`
	Detail   string             `json:"detail"`
}

// JarScanReport 是一次扫描的完整结果。
type JarScanReport struct {
	Entries        int          `json:"entries"`
	ClassFiles     int          `json:"classFiles"`
	ScannedClasses int          `json:"scannedClasses"`
	Findings       []JarFinding `json:"findings"`
	HasModMarker   bool         `json:"hasModMarker"`
	NestedJars     int          `json:"nestedJars"`
	NativeLibs     int          `json:"nativeLibs"`

	// ruleSeen 对同一规则只报一次，避免一个 jar 里上百个 class 刷屏。
	ruleSeen map[string]bool

	// 以下为跨嵌套层级共享的扫描状态，不参与 JSON 序列化。
	limitedEntries   bool
	nestedLimitDepth bool
	nestedLimitCount bool
}

// Blocked 报告是否存在必须阻断安装的 critical 发现。
func (r *JarScanReport) Blocked() bool {
	if r == nil {
		return false
	}
	return anyBlocking(r.Findings, func(f JarFinding) bool { return f.Severity == JarSeverityCritical })
}

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
