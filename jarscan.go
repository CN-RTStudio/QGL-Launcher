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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
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

// scanNestedJar 在有界深度 / 数量 / 字节预算内递归扫描一个嵌套 jar，
// 直接把内部条目收集进同一个总报告，critical 会正常向上传播触发阻断。
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

// scanManifestEntry 读取并解析 MANIFEST.MF 的关键头（处理 CRLF 与续行折叠）。
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

// readManifestHeaders 读取 MANIFEST（有上限），折叠续行，返回大写键映射。
func readManifestHeaders(f *zip.File) map[string]string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	limited := io.LimitReader(rc, jarScanTextCap)
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), jarScanTextCap)

	heads := map[string]string{}
	var curKey, curVal string
	flush := func() {
		if curKey != "" {
			heads[strings.ToUpper(curKey)] = strings.TrimSpace(curVal)
		}
		curKey, curVal = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// MANIFEST 续行：以空格或制表符开头的行拼接到上一个值。
		if line[0] == ' ' || line[0] == '\t' {
			curVal += strings.TrimLeft(line, " \t")
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		curKey = line[:colon]
		curVal = strings.TrimSpace(line[colon+1:])
	}
	flush()
	return heads
}

// isJarRootEntry 判断条目是否位于 jar 根目录（不含目录分隔符）。
func isJarRootEntry(lowerName string) bool {
	return !strings.Contains(lowerName, "/")
}

// pathExtLower 返回小写扩展名（含点），无扩展名返回空串。
func pathExtLower(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 || strings.LastIndexByte(name, '/') > dot {
		return ""
	}
	return name[dot:]
}

// jarBehaviorPattern 描述一条字节码行为启发式：常量池文本同时包含
// require 与 andAlso（andAlso 为空时只要求 require）即命中。
// 这是“值得人工注意”的能力信号，不直接证明恶意，因此最高只到 warn。
type jarBehaviorPattern struct {
	rule    string
	sev     JarFindingSeverity
	require string
	andAlso string
	detail  string
}

var jarBehaviorPatterns = []jarBehaviorPattern{
	{
		rule:    "behavior-process-exec",
		sev:     JarSeverityWarn,
		require: "java/lang/Runtime",
		andAlso: "exec",
		detail:  "class 常量池引用 Runtime.exec，具备直接拉起外部进程的能力",
	},
	{
		rule:    "behavior-process-builder",
		sev:     JarSeverityWarn,
		require: "java/lang/ProcessBuilder",
		andAlso: "",
		detail:  "class 常量池引用 ProcessBuilder，具备组装并启动系统命令的能力",
	},
	{
		rule:    "behavior-url-classloader",
		sev:     JarSeverityWarn,
		require: "java/net/URLClassLoader",
		andAlso: "",
		detail:  "class 常量池引用 URLClassLoader，可从远端地址动态加载字节码",
	},
	{
		rule:    "behavior-define-class",
		sev:     JarSeverityWarn,
		require: "defineClass",
		andAlso: "",
		detail:  "class 常量池引用 defineClass，可在运行时把内存字节定义为可执行类",
	},
	{
		rule:    "behavior-script-engine",
		sev:     JarSeverityInfo,
		require: "javax/script/",
		andAlso: "",
		detail:  "class 常量池引用脚本引擎（javax.script），具备运行期执行脚本的能力",
	},
	{
		rule:    "behavior-reflective-open",
		sev:     JarSeverityInfo,
		require: "java/lang/reflect/",
		andAlso: "setAccessible",
		detail:  "class 常量池出现反射 + setAccessible，可绕过访问检查触碰内部 API",
	},
}

func (r *JarScanReport) addRuleOnce(sev JarFindingSeverity, rule, entry, detail string) {
	if r.ruleSeen[rule] {
		return
	}
	r.ruleSeen[rule] = true
	r.add(sev, rule, entry, detail)
}

// scanClassBehavior 读取单个 class（有字节上限），只解析常量池里的 UTF8 项做能力
// 特征匹配，绝不加载 / 验证 / 执行字节码。返回实际读取的字节数（用于全局预算）；
// class 损坏或被截断时返回 0，跳过而不影响其他条目。
func scanClassBehavior(rep *JarScanReport, f *zip.File, entryName string, spent int) int {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()

	capLeft := jarScanClassBytesCap - spent
	if capLeft <= 0 {
		return 0
	}
	limit := int64(jarScanPerClassCap)
	if int64(capLeft) < limit {
		limit = int64(capLeft)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return 0
	}

	texts := classConstantPoolUTF8(data)
	if texts == nil {
		// 不是可识别的 class 结构（可能被截断），不计入已扫描配额之外的噪音。
		return 0
	}
	var blob strings.Builder
	blob.Grow(len(data))
	for _, s := range texts {
		blob.WriteString(s)
		blob.WriteByte('\n')
	}
	joined := blob.String()
	lowerJoined := strings.ToLower(joined)
	for _, p := range jarBehaviorPatterns {
		needle := strings.ToLower(p.require)
		if !strings.Contains(lowerJoined, needle) {
			continue
		}
		if p.andAlso != "" && !strings.Contains(lowerJoined, strings.ToLower(p.andAlso)) {
			continue
		}
		rep.addRuleOnce(p.sev, p.rule, entryName, p.detail)
	}
	return len(data)
}

// classReader 是带边界检查的 class 文件只读游标，越界后 ok=false 并短路。
type classReader struct {
	b   []byte
	off int
	ok  bool
}

func (r *classReader) u1() int {
	if !r.ok || r.off+1 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])
	r.off++
	return v
}

func (r *classReader) u2() int {
	if !r.ok || r.off+2 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<8 | int(r.b[r.off+1])
	r.off += 2
	return v
}

func (r *classReader) u4() int {
	if !r.ok || r.off+4 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<24 | int(r.b[r.off+1])<<16 | int(r.b[r.off+2])<<8 | int(r.b[r.off+3])
	r.off += 4
	return v
}

func (r *classReader) take(n int) []byte {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

// classConstantPoolUTF8 最小化解析 class 文件，仅提取常量池 CONSTANT_Utf8 项。
// JVM 规范里类名 / 方法名字符串都以 UTF8 常量存放，能力特征匹配只需要这些文本。
// 结构非法（魔数不符 / 长度越界）返回 nil。
func classConstantPoolUTF8(data []byte) []string {
	if len(data) < 10 {
		return nil
	}
	r := &classReader{b: data, ok: true}
	if r.u4() != 0xCAFEBABE {
		return nil
	}
	r.u2() // minor_version
	r.u2() // major_version
	cpCount := r.u2()
	if cpCount == 0 {
		return nil
	}

	out := make([]string, 0, 16)
	// 常量池索引从 1 开始；Long/Double 占两个槽位。
	for idx := 1; idx < cpCount && r.ok; idx++ {
		tag := r.u1()
		switch tag {
		case 1: // CONSTANT_Utf8
			n := r.u2()
			if b := r.take(n); b != nil {
				out = append(out, string(b))
			}
		case 3, 4: // Integer, Float
			r.take(4)
		case 5, 6: // Long, Double（占两个槽位）
			r.take(8)
			idx++
		case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package
			r.take(2)
		case 9, 10, 11, 12, 17, 18: // Fieldref..NameAndType, Dynamic, InvokeDynamic
			r.take(4)
		case 15: // MethodHandle: reference_kind(u1) + reference_index(u2)
			r.take(3)
		default:
			// 未知 / 截断的 tag：该 class 不可信，放弃解析。
			return nil
		}
	}
	if !r.ok {
		return nil
	}
	return out
}

// enforceModJarScan 是 Mod 安装链统一入口：扫描磁盘上的 jar，把每条发现写入
// 安全审计日志，出现 critical 或文件本身损坏时返回错误（调用方负责删除未落定
// 成的临时文件 / 终止导入）。source 仅用于审计，取值如 "mod-download" /
// "mod-import"；label 是文件名或 URL，会被脱敏限长。
func enforceModJarScan(jarPath, source, label string) (*JarScanReport, error) {
	rep, err := scanJarAt(jarPath)
	if err != nil {
		recordSecurityEvent(auditCategoryJarScan, auditSeverityCritical, auditActionBlocked,
			source, "jar 无法解析，拒绝进入 mods 目录: "+sanitizeLogLine(label))
		return nil, err
	}

	var critical int
	for _, f := range rep.Findings {
		action := auditActionStripped
		if f.Severity == JarSeverityCritical {
			action = auditActionBlocked
			critical++
		}
		detail := fmt.Sprintf("[%s] %s %s", f.Rule, f.Entry, f.Detail)
		recordSecurityEvent(auditCategoryJarScan, string(f.Severity), action, source,
			sanitizeLogLine(detail))
	}

	if critical > 0 {
		return rep, fmt.Errorf("Mod jar 静态扫描发现 %d 个高危项（如根目录可执行载荷），已阻止安装: %s",
			critical, sanitizeLogLine(label))
	}
	return rep, nil
}
