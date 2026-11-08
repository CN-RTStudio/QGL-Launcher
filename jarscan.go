package main

// jarscan.go —— 在“把文件放进 mods 目录并随 JVM 启动”之前做一层静态内容安检。
//
// 哈希校验只能证明“下载到的字节和 Modrinth 声明的一致”，证明不了“作者上传的
// 东西本身安全”。一个 Minecraft Mod 本质是会被加载进同一个 JVM 的 jar：
//
//   - MANIFEST.MF 里带 Premain-Class / Agent-Class / Launcher-Agent-Class 就是
//     JVM 代理（instrumentation / attach）入口，能在 Mod 正常初始化前挂钩任意类，
//     是账号窃取类恶意 Mod 的常见自启动手法；
//   - ModLauncher 的 TransformationService、coremods 下的 Nashorn .js 会在类加载
//     阶段执行任意代码 / 脚本，且不经 Mod 加载器的常规生命周期；
//   - jar 根部直接放 .exe/.bat/.cmd/.ps1 等可执行脚本、或 pack200（.pack）这种
//     “启动时才解包”的载体，明显偏离正常 Mod 形态，属于高置信度危险信号；
//   - 根目录 Main-Class 让它可被当成普通可执行 jar 双击运行。
//
// 这里只做只读静态扫描，绝不执行、不解压任何条目（用 archive/zip 读中央目录与
// 小体积文本条目），对读取条数和单条目读取字节数都有硬上限，避免被恶意构造的
// 巨型 / 海量条目拖垮。结论分 info / warn / critical：critical 阻断安装，
// warn / info 只记审计事件放行，避免误伤带本地库（.dll/.so）的正常 Mod。

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

// JarFindingSeverity 与审计事件级别对齐。
type JarFindingSeverity string

const (
	JarSeverityInfo     JarFindingSeverity = "info"
	JarSeverityWarn     JarFindingSeverity = "warn"
	JarSeverityCritical JarFindingSeverity = "critical"
)

// JarFinding 是一条命中规则的发现。
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
	limitedEntries    bool
	nestedLimitDepth  bool
	nestedLimitCount  bool
}

// Blocked 报告是否存在必须阻断安装的 critical 发现。
func (r *JarScanReport) Blocked() bool {
	if r == nil {
		return false
	}
	for _, f := range r.Findings {
		if f.Severity == JarSeverityCritical {
			return true
		}
	}
	return false
}

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
