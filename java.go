package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
func (a *App) scanJavaInstallations() []JavaEntry {
	var results []JavaEntry
	seen := make(map[string]bool)

	// 1. 搜索常见安装路径
	commonPaths := []string{
		"C:\\Program Files\\Java",
		"C:\\Program Files (x86)\\Java",
		"C:\\Program Files\\Eclipse Adoptium",
		"C:\\Program Files (x86)\\Eclipse Adoptium",
		"C:\\Program Files\\Microsoft",
		"C:\\Program Files\\AdoptOpenJDK",
		"C:\\Program Files\\Zulu",
		"C:\\Program Files\\BellSoft",
		"C:\\Program Files\\Amazon Corretto",
		"C:\\Program Files\\Semeru",
	}
	for _, baseDir := range commonPaths {
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			javawPath := filepath.Join(baseDir, entry.Name(), "bin", "javaw.exe")
			if _, err := os.Stat(javawPath); err == nil {
				if !seen[javawPath] {
					seen[javawPath] = true
					javaEntry := validateJava(javawPath)
					if javaEntry != nil {
						results = append(results, *javaEntry)
					}
				}
			}
		}
	}

	// 2. JAVA_HOME 环境变量
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		javawPath := filepath.Join(javaHome, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				results = append(results, *javaEntry)
			}
		}
	}

	// 3. PATH 环境变量
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		paths := strings.Split(pathEnv, ";")
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			javawPath := filepath.Join(p, "javaw.exe")
			if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
				// 排除 system32 中的重定向
				if strings.Contains(strings.ToLower(javawPath), "system32") {
					continue
				}
				seen[javawPath] = true
				javaEntry := validateJava(javawPath)
				if javaEntry != nil {
					results = append(results, *javaEntry)
				}
			}
		}
	}

	// 4. 搜索 QGL 自身目录
	exePath, _ := os.Executable()
	appDir := filepath.Dir(exePath)
	searchDirForJava(appDir, &results, seen, 3)

	// 5. 搜索 .minecraft 目录
	mcDir := a.GetMinecraftDir()
	searchDirForJava(mcDir, &results, seen, 3)

	// 6. 搜索 AppData 下的 Java
	appData := os.Getenv("APPDATA")
	if appData != "" {
		searchDirForJava(appData, &results, seen, 2)
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData != "" {
		searchDirForJava(localAppData, &results, seen, 2)
	}

	// 7. 搜索所有本地磁盘驱动器（参考PCL的磁盘全盘遍历）
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err != nil {
			continue // 驱动器不存在
		}
		// 搜索驱动器根目录下的 Java 相关文件夹
		searchDriveForJava(drivePath, &results, seen)
	}

	// 排序：优先64位，然后按权重排序
	sort.Slice(results, func(i, j int) bool {
		// 64位优先
		if results[i].Is64Bit != results[j].Is64Bit {
			return results[i].Is64Bit
		}
		// 按权重排序（参考PCL的JavaSorter权重数组）
		weightI := getJavaWeight(results[i].MajorVer)
		weightJ := getJavaWeight(results[j].MajorVer)
		if weightI != weightJ {
			return weightI > weightJ
		}
		return results[i].MajorVer > results[j].MajorVer
	})

	return results
}

// isReparsePointDir 判断目录条目是否为 reparse point（junction / 符号链接 /
// 挂载点）。全盘递归扫描（AppData、磁盘根）若跟随 junction，可能被引到另一个
// 卷或系统目录（例如用户把某目录联接成 C:\ 根），既拖慢扫描又会发现扫描范围
// 之外的 Java；maxDepth 也挡不住 junction 构成的环之外的横向跳转。
// 发现阶段只认真实目录：当前层级的 javaw.exe 探测照常（显式安装的 JDK 不受
// 影响），但绝不递归进入 reparse point。
func isReparsePointDir(entry os.DirEntry) bool {
	info, err := entry.Info()
	if err != nil {
		return false
	}
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	return false
}

// searchDriveForJava 搜索磁盘驱动器上的 Java（参考PCL的磁盘遍历逻辑）
// 只搜索根目录下的 Java 相关文件夹，避免全盘递归太慢
func searchDriveForJava(drivePath string, results *[]JavaEntry, seen map[string]bool) {
	entries, err := os.ReadDir(drivePath)
	if err != nil {
		return
	}
	// 需要进入搜索的根目录关键字（参考PCL的JavaSearchFolder关键字列表）
	rootKeywords := []string{
		"java", "jdk", "jre", "program", "software", "soft", "app",
		"develop", "dev", "tools", "runtime", "env", "游戏", "game",
		"mc", "minecraft", "launch", "启动", "运行", "应用",
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		// 直接检查该目录下是否有 bin/javaw.exe
		javawPath := filepath.Join(drivePath, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}
		// 判断是否需要进入该目录搜索
		shouldEnter := false
		for _, kw := range rootKeywords {
			if strings.Contains(lowerName, kw) {
				shouldEnter = true
				break
			}
		}
		if shouldEnter {
			// 不跟随 junction / 符号链接，避免扫到其它卷或陷入联接环。
			if isReparsePointDir(entry) {
				continue
			}
			searchDirForJava(filepath.Join(drivePath, name), results, seen, 4)
		}
	}
}

// searchDirForJava 在指定目录下搜索 Java（参考PCL的JavaSearchFolder关键字过滤）
func searchDirForJava(dir string, results *[]JavaEntry, seen map[string]bool, maxDepth int) {
	if maxDepth <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// 关键字列表（参考PCL）
	keywords := []string{
		"java", "jdk", "jre", "runtime", "env", "run", "soft",
		"corretto", "adoptium", "zulu", "semeru", "microsoft",
		"eclipse", "oracle", "hotspot", "openjdk", "bellsoft",
		"program", "game", "mc", "minecraft", "version",
		"x64", "x86", "bin", "users",
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowerName := strings.ToLower(name)
		// 检查 bin 目录下是否有 javaw.exe
		javawPath := filepath.Join(dir, name, "bin", "javaw.exe")
		if _, err := os.Stat(javawPath); err == nil && !seen[javawPath] {
			seen[javawPath] = true
			javaEntry := validateJava(javawPath)
			if javaEntry != nil {
				*results = append(*results, *javaEntry)
			}
		}
		// 决定是否进入子目录
		shouldEnter := false
		// 数字开头的目录（版本号）
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			shouldEnter = true
		}
		// bin 目录无条件进入
		if lowerName == "bin" {
			shouldEnter = true
		}
		// users 目录无条件进入
		if lowerName == "users" {
			shouldEnter = true
		}
		// 关键字匹配
		if !shouldEnter {
			for _, kw := range keywords {
				if strings.Contains(lowerName, kw) {
					shouldEnter = true
					break
				}
			}
		}
		if shouldEnter {
			// 不跟随 junction / 符号链接：AppData 下的目录联接可能指向
			// Program Files 或其它卷，真实目录会由对应的固定扫描路径发现。
			if isReparsePointDir(entry) {
				continue
			}
			searchDirForJava(filepath.Join(dir, name), results, seen, maxDepth-1)
		}
	}
}

// maxJavaVersionOutput 限制 `java -version` 的输出体积。
// 正常输出只有几百字节；用户选择的"Java 路径"是前端绑定方法可直接传入的
// 参数，若放任输出不设上限，一个伪造的 java.exe 打印海量内容即可撑爆内存。
const maxJavaVersionOutput int64 = 1 << 20 // 1 MiB

// limitedWriter 最多写入 max+1 字节，多出的字节直接丢弃，
// 调用方通过 n>max 判定输出超限。stdout/stderr 可能并发写入，需加锁。
type limitedWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
	max int64
	n   int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.n += int64(len(p))
	remain := w.max + 1 - int64(w.buf.Len())
	if remain > 0 {
		if int64(len(p)) < remain {
			remain = int64(len(p))
		}
		w.buf.Write(p[:remain])
	}
	return len(p), nil
}

// isJavaBinaryName 校验传入路径指向的确实是 java / javaw 可执行文件。
// GetJavaInfo 等绑定方法的路径参数前端可控，必须挡住 cmd.exe、脚本等
// 非 Java 可执行文件，避免它退化为"带固定参数的任意程序执行"原语。
func isJavaBinaryName(p string) bool {
	switch strings.ToLower(filepath.Base(p)) {
	case "java.exe", "javaw.exe":
		return true
	}
	return false
}

// validateJava 验证 Java 路径并获取版本信息（参考PCL的JavaEntry.Check）
// 安全加固: 添加 10 秒超时，防止 Java 进程挂起导致应用卡住
func validateJava(javawPath string) *JavaEntry {
	javawPath = filepath.Clean(javawPath)
	if !isJavaBinaryName(javawPath) {
		return nil
	}
	// 检查 javaw.exe 是否存在
	if _, err := os.Stat(javawPath); err != nil {
		return nil
	}
	// 检查 java.exe 是否存在（同目录下）
	dir := filepath.Dir(javawPath)
	javaExePath := filepath.Join(dir, "java.exe")
	if !isJavaBinaryName(javaExePath) {
		return nil
	}
	if _, err := os.Stat(javaExePath); err != nil {
		return nil
	}
	// 供应链防护：标准布局下 java.exe 位于 <JDK_HOME>//bin。若该文件（或其上级）
	// 是指向 JDK 目录之外的符号链接 / junction，解析后的真实路径会逃出 JDK_HOME，
	// 这常见于被篡改的 JAVA_HOME 或预置的链接型“影子 JDK”，命中即拒绝信任。
	if strings.EqualFold(filepath.Base(dir), "bin") {
		jdkHome := filepath.Dir(dir)
		if _, ok := ResolvedPathWithinRoot(javaExePath, jdkHome); !ok {
			return nil
		}
	}
	// 判断是否为 JDK（检查 javac.exe）
	javacPath := filepath.Join(dir, "javac.exe")
	isJDK := false
	if _, err := os.Stat(javacPath); err == nil {
		isJDK = true
	}
	// 运行 java -version 获取版本信息（带超时）
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, javaExePath, "-version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// 版本探测同样会真正启动一次 JVM：不净化环境的话，
	// JAVA_TOOL_OPTIONS 里的 javaagent 会在探测阶段就被加载并执行。
	probeEnv, _ := currentGameEnvironment(nil)
	cmd.Env = probeEnv
	var outBuf bytes.Buffer
	lw := &limitedWriter{buf: &outBuf, max: maxJavaVersionOutput}
	cmd.Stdout = lw
	cmd.Stderr = lw
	runErr := cmd.Run()
	if runErr != nil && ctx.Err() != nil {
		// 超时，跳过这个 Java
		return nil
	}
	if lw.n > maxJavaVersionOutput {
		// 输出体积异常，疑似伪造可执行文件
		return nil
	}
	outputStr := outBuf.String()
	// 解析版本号（参考PCL的正则匹配逻辑）
	version, majorVer := parseJavaVersion(outputStr)
	if majorVer <= 0 {
		return nil
	}
	// 检测是否为64位
	is64Bit := strings.Contains(outputStr, "64-Bit") || strings.Contains(outputStr, "64-bit")
	return &JavaEntry{
		Path:     javawPath,
		Version:  version,
		MajorVer: majorVer,
		Is64Bit:  is64Bit,
		IsJDK:    isJDK,
	}
}

// parseJavaVersion 从 java -version 输出中解析版本号
func parseJavaVersion(output string) (string, int) {
	// 匹配 "1.8.0_321" 或 "17.0.3" 或 "21.0.1" 等格式
	re1 := regexp.MustCompile(`version "([^"]+)"`)
	matches := re1.FindStringSubmatch(output)
	if len(matches) >= 2 {
		rawVersion := matches[1]
		return normalizeJavaVersion(rawVersion)
	}
	// 匹配 openjdk 格式
	re2 := regexp.MustCompile(`openjdk (\d[\d._]*)`)
	matches = re2.FindStringSubmatch(output)
	if len(matches) >= 2 {
		rawVersion := matches[1]
		return normalizeJavaVersion(rawVersion)
	}
	return "", 0
}

// normalizeJavaVersion 标准化 Java 版本号并提取主版本号
func normalizeJavaVersion(raw string) (string, int) {
	// 将 _ 替换为 .
	raw = strings.ReplaceAll(raw, "_", ".")
	// 取 - 前的部分
	if idx := strings.Index(raw, "-"); idx > 0 {
		raw = raw[:idx]
	}
	// 解析版本号段
	parts := strings.Split(raw, ".")
	majorVer := 0
	if len(parts) >= 1 {
		// 如果以 "1." 开头（旧版本格式，如 1.8.0）
		if parts[0] == "1" && len(parts) >= 2 {
			// 主版本号是第二段
			majorVer, _ = strconv.Atoi(parts[1])
		} else {
			// 新版本格式，主版本号是第一段（如 17, 21）
			majorVer, _ = strconv.Atoi(parts[0])
		}
	}
	if majorVer <= 0 || majorVer >= 100 {
		return "", 0
	}
	return raw, majorVer
}

// getJavaWeight 获取 Java 版本的排序权重（参考PCL的JavaSorter权重数组）
func getJavaWeight(majorVer int) int {
	// PCL 的权重数组（索引 = Java 大版本号）
	weights := map[int]int{
		7:  14,
		8:  30,
		9:  10,
		10: 12,
		11: 15,
		12: 13,
		13: 9,
		14: 8,
		15: 7,
		16: 11,
		17: 31,
		18: 29,
		19: 16,
		20: 17,
		21: 28,
		22: 27,
		23: 26,
		24: 25,
		25: 24,
		26: 23,
		27: 22,
		28: 21,
		29: 20,
		30: 19,
	}
	if w, ok := weights[majorVer]; ok {
		return w
	}
	if majorVer > 30 {
		return 18
	}
	return 0
}

// GetJavaRequirement 根据 MC 版本获取 Java 版本需求（参考PCL的McLaunchJava）
