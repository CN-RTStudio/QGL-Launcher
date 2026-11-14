package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func (a *App) getVersionFolderList(mcDir string) map[string]bool {
	versionsDir := filepath.Join(mcDir, "versions")
	result := map[string]bool{}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if entry.IsDir() {
			result[entry.Name()] = true
		}
	}

	return result
}

func (a *App) runForgeInstaller(installerPath string, mcDir string) error {
	a.writeLog("===== 开始运行 ForgeInstaller =====")

	a.ensureForgeMappings(installerPath, mcDir)

	bbInstallerPath, err := a.extractForgeInstaller()
	if err != nil {
		a.writeLog("提取 ForgeInstaller 失败: %v", err)
		return err
	}
	a.writeLog("ForgeInstaller 路径: %s", bbInstallerPath)
	a.writeLog("Forge 安装器路径: %s", installerPath)

	javaEntry, err := a.selectJavaForInstaller()
	if err != nil {
		a.writeLog("选择 Java 失败: %v", err)
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	a.writeLog("使用 Java: %s (版本: %s, 主版本: %d)", javaEntry.Path, javaEntry.Version, javaEntry.MajorVer)

	classpath := bbInstallerPath + ";" + installerPath

	args := []string{}
	if javaEntry.MajorVer >= 9 {
		args = append(args, "--add-exports", "cpw.mods.bootstraplauncher/cpw.mods.bootstraplauncher=ALL-UNNAMED")
	}
	args = append(args, "-cp", classpath, "com.bangbang93.ForgeInstaller", mcDir)

	a.writeLog("完整命令: %s %s", javaEntry.Path, strings.Join(args, " "))

	// 启动前对安装器 JVM 做目标审计：java 可执行、工作目录、绝对 classpath 的目录归属
	// （bbInstaller / installer 各自的父目录 + mcDir）、主类与程序参数，阻止任何指向
	// UNC / 目录穿越 / 允许目录之外的 jar/classpath。
	forgeRoots := []string{mcDir, filepath.Dir(bbInstallerPath), filepath.Dir(installerPath)}
	forgeAudit := AuditExternalJVM(ExternalJVMPlan{
		JavaExe:      javaEntry.Path,
		WorkDir:      mcDir,
		Classpath:    []string{bbInstallerPath, installerPath},
		MainClass:    "com.bangbang93.ForgeInstaller",
		ProgramArgs:  []string{mcDir},
		AllowedRoots: forgeRoots,
	})
	if forgeAudit.HasCritical() {
		return fmt.Errorf("Forge 安装器启动审计未通过: %s", forgeAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaEntry.Path, args...)
	cmd.Dir = mcDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Forge 安装器本身是个独立 JVM：不下发净化环境就会继承
	// JAVA_TOOL_OPTIONS 一族，绕过 JVM 参数过滤注入 javaagent。
	a.applySanitizedJVMEnv(cmd, "ForgeInstaller", nil)

	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	a.writeLog("----- ForgeInstaller 输出开始 -----")
	if outputStr != "" {
		for _, line := range strings.Split(outputStr, "\n") {
			a.writeLog("  %s", line)
		}
	} else {
		a.writeLog("  (无输出)")
	}
	a.writeLog("----- ForgeInstaller 输出结束 -----")
	if runErr != nil {
		a.writeLog("进程退出错误: %v", runErr)
	}

	lines := strings.Split(outputStr, "\n")
	var lastLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			lastLines = append(lastLines, line)
		}
	}

	foundTrue := false
	checkCount := 4
	if len(lastLines) < checkCount {
		checkCount = len(lastLines)
	}
	for _, line := range lastLines[len(lastLines)-checkCount:] {
		if line == "true" {
			foundTrue = true
			break
		}
	}

	if foundTrue {
		a.writeLog("检测到安装器成功标志 'true'，安装成功")
		return nil
	}

	a.writeLog("未检测到安装器成功标志 'true'，安装失败")

	if runErr != nil {
		errMsg := fmt.Errorf("Forge 安装器运行失败\nJava: %s (v%d)\n错误: %v\n\n完整输出:\n%s",
			javaEntry.Path, javaEntry.MajorVer, runErr, outputStr)
		a.writeLog("Forge 安装最终失败: %v", errMsg)
		return errMsg
	}

	errMsg := fmt.Errorf("Forge 安装器未返回成功标志\nJava: %s (v%d)\n\n完整输出:\n%s",
		javaEntry.Path, javaEntry.MajorVer, outputStr)
	a.writeLog("Forge 安装最终失败: %v", errMsg)
	return errMsg
}
