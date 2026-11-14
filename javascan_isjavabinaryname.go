package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func isJavaBinaryName(p string) bool {
	switch strings.ToLower(filepath.Base(p)) {
	case "java.exe", "javaw.exe":
		return true
	}
	return false
}

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
