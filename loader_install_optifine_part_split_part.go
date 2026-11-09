package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func (a *App) downloadLoaderItem(item *DownloadItem) error {
	if item.URL == "" {
		return fmt.Errorf("下载地址为空")
	}

	if !isHTTPSURL(item.URL) {
		return fmt.Errorf("不安全的下载 URL（非 HTTPS）")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}

	// 落盘目标名不再直接取展示名：走 loaderdest 内核，按 URL 路径判定扩展名
	// （忽略 query）、slug 白名单化、追加 UMFS 指纹去碰撞，并断言结果仍严格位于
	// TEMP 内。旧实现 filepath.Base(CustomName) 保留空格 / 括号、文件名可预测，
	// 且 URL 带 ?query 时会漏判 .jar。
	artifactExt := loaderArtifactExt(item.URL)
	destPath, ok := resolveLoaderTempDest(tempDir, item.CustomName, item.URL)
	if !ok {
		return fmt.Errorf("无法在临时目录内构造安全的安装器落盘路径")
	}
	fileName := filepath.Base(destPath)

	a.emitProgress("downloading", fileName, 0, 0)

	if err := a.downloadFile(item.URL, destPath, true); err != nil {
		return fmt.Errorf("下载加载器失败: %v", err)
	}

	if artifactExt == ".jar" {
		javaEntry := a.SearchJava()
		if len(javaEntry) == 0 {
			return fmt.Errorf("下载完成但未找到 Java 来运行安装器，请手动运行: %s", destPath)
		}
		// “下载即运行”的第三方 jar 风险最高：审计目标 jar 必须是 tempDir 内的绝对
		// .jar，阻止 UNC / 穿越 / 目录之外目标，java 可执行同样过绝对/扩展名校验。
		dlAudit := AuditExternalJVM(ExternalJVMPlan{
			JavaExe:      javaEntry[0].Path,
			WorkDir:      tempDir,
			JarAbsPath:   destPath,
			AllowedRoots: []string{tempDir},
		})
		if dlAudit.HasCritical() {
			return fmt.Errorf("下载的安装器启动审计未通过: %s", dlAudit.FirstCriticalCode())
		}
		cmd := exec.Command(javaEntry[0].Path, "-jar", destPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		// 下载下来的第三方 jar 安装器也是独立 JVM，同样不能继承隐式 JVM
		// 参数环境变量，否则下载即运行这条链会被 JAVA_TOOL_OPTIONS 劫持。
		a.applySanitizedJVMEnv(cmd, "DownloadedJarInstaller", nil)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("启动安装器失败: %v", err)
		}
	}

	return nil
}
