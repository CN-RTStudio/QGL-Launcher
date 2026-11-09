package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

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
