package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) LaunchGame(versionID string) error {
	if err := sanitizePathComponent(versionID); err != nil {
		return fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)

	// 拉起 JVM 前对 mods 目录做存量安全扫描（通用恶意形态 + Log4Shell/JNDI），
	// 覆盖手动拖入 / 其它启动器写入、从未经本程序校验的 jar；命中高危直接拒绝启动。
	if err := a.enforceInstalledModsBeforeLaunch(versionID); err != nil {
		return err
	}

	// mods 完整性审计闸门：基线存在时对账目录，发现被篡改的 mod 默认拦截启动，
	// 除非用户显式开启强制放行（SetModsAuditForceLaunch）。新增 / 缺失仅提示。
	if err := a.enforceModsAuditBeforeLaunch(versionID); err != nil {
		return err
	}

	// 实例并发启动锁：同一版本实例同时只能有一个 JVM 在跑（防止两个进程并发
	// 读写世界存档 / 配置 / 日志互相踩踏）。上锁失败直接拦截；锁在游戏进程
	// 退出后由 watchGameProcess 释放，进程被强杀时靠过期时长兜底接管。
	if _, err := a.acquireInstanceLock(versionID); err != nil {
		return err
	}

	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	runtime.EventsEmit(a.ctx, "launchStatus", "fixing")
	a.emitProgress("downloading", "补全文件中", 0, 0)
	a.fixMissingLibraries(mcDir, versionJSON)

	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0700); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	allArgs, _, _, gameDir := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)

	currentUser, _ := a.GetCurrentUser()
	if currentUser.Type == UserTypeExternal {
		username := currentUser.Username
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil {
			injectorPath, injErr := a.GetAuthlibInjectorPath()
			if injErr == nil {
				serverURL := extData.ServerURL
				prefetched := ""
				if isHTTPSURL(serverURL) {
					resp, err := safeHTTPClient().Get(serverURL)
					if err == nil {
						// 皮肤站首页本应几 KB；上限 1MiB，防止恶意服务器返回超大响应把
						// JVM 命令行撑爆。走统一有界读内核（多读 1 字节精确判定超限），
						// 读体中断或超量都不预取，而不是像旧实现那样吞掉读错、拿半截内容。
						body, readErr := readBoundedBody(resp.Body, maxAuthlibPrefetchBytes)
						resp.Body.Close()
						if readErr == nil {
							prefetched = base64.StdEncoding.EncodeToString(body)
						}
					}
				}
				injectorArgs := []string{"-javaagent:" + injectorPath + "=" + serverURL, "-Dauthlibinjector.side=client"}
				if prefetched != "" {
					injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
				}
				allArgs = append(injectorArgs, allArgs...)
			}
		}
	}

	a.setGameLanguage(gameDir, versionID)

	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	// 启动预检：Java 二进制必须是常规文件（Windows 拒绝重解析点/符号链接，防
	// 配置项被换成指向任意程序的链接入口）；游戏目录 / natives 目录必须就绪；
	// 磁盘剩余空间低于安全水位时提示。critical 问题直接拒绝启动。
	preflightIssues, preflightBlocked := aggregatePreflight(
		checkJavaBinary(javaPath),
		checkGameDirs(gameDir, nativesDir),
		checkDiskHeadroom(gameDir, preflightMinFreeBytes),
		checkSymlinkTraps(gameDir),
	)
	for _, it := range preflightIssues {
		recordSecurityEvent("launch-preflight", auditSeverityWarn, auditActionDetected,
			"minecraft", "预检["+it.Code+"] "+it.Text)
	}
	if preflightBlocked {
		recordSecurityEvent("launch-preflight", auditSeverityCritical, auditActionBlocked,
			"minecraft", "启动预检未通过，拒绝启动")
		return fmt.Errorf("启动预检未通过，拒绝启动")
	}

	// 关键配置防篡改基线：Java 路径 / 游戏目录 / 版本选择等启动执行目标字段若在
	// 两次本进程会话之间被外部改动（木马把 javaPath 换成自己投放的 exe），
	// 静态预检看不出来——这里按基线 diff 拒绝启动，防配置投毒。
	if cfg, cfgErr := a.GetGlobalConfig(); cfgErr == nil {
		ucfg, ucfgErr := a.GetUserConfig(currentUser.Username)
		if ucfgErr != nil {
			ucfg = &UserConfig{}
		}
		if baselineErr := a.CheckConfigGuardBaseline(a.configSnapshotOf(cfg, ucfg)); baselineErr != nil {
			return baselineErr
		}
	}

	// 启动参数快照：把“用什么启动”落一份脱敏快照（Java 路径 / 版本 / 内存 /
	// auth 类型 / mods 数量 / 预检结果），与 session journal 互补——日后审计只
	// 看结果不看配置的问题由本模块补上。快照不含任何 token，只记类型。
	authTypeLabel := "offline"
	switch currentUser.Type {
	case UserTypePremium:
		authTypeLabel = "microsoft"
	case UserTypeExternal:
		authTypeLabel = "external"
	}
	// 堆内存与启动参数同源（heapsizeguard 归一后的 safeMax），快照记录 MB 口径。
	maxMemMB := 2048
	if config, cfgErr := a.GetGlobalConfig(); cfgErr == nil && config != nil {
		_, safeMaxGB, _ := ResolveHeapSizesGB(config.MinMemory, config.MaxMemory)
		maxMemMB = safeMaxGB * 1024
	}
	modsCount := 0
	if modsDir, errDir := filepath.Abs(filepath.Join(mcDir, "mods")); errDir == nil {
		if entries, errLs := os.ReadDir(modsDir); errLs == nil {
			modsCount = len(entries)
		}
	}
	a.recordLaunchSnapshot(buildLaunchSnapshot(
		versionID, javaPath, javaEntry.Version, authTypeLabel,
		maxMemMB, modsCount, currentUser.Type == UserTypePremium, preflightBlocked, len(preflightIssues),
	))

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	fullCmdLine := strings.Join(cmdParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	// 最终防线：真正被 CreateProcess 解释的是上面拼好的整条字符串（SysProcAttr.CmdLine），
	// 其中混入了版本 JSON、账号、外部认证服务器 URL 等多源数据。在启动前按系统分词规则
	// 还原 argv 并审计：拒绝 CR/LF/NUL 注入、引号不配平、超长串/参数，以及 argv[0] 必须
	// 仍是安全的 java 可执行。critical 一律不启动游戏。
	if _, cmdAudit := AuditCommandLine(fullCmdLine, true); cmdAudit.HasCritical() {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityCritical, auditActionBlocked,
			"minecraft", "游戏启动命令行最终审计未通过: "+cmdAudit.FirstCriticalCode())
		return fmt.Errorf("游戏启动命令行安全审计未通过，拒绝启动: %s", cmdAudit.FirstCriticalCode())
	}

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fullCmdLine}

	// 子进程默认会继承启动器的全部环境变量，而 JAVA_TOOL_OPTIONS /
	// _JAVA_OPTIONS / JDK_JAVA_OPTIONS 等会被 JVM 在启动时自动当作额外参数
	// 加载，绕过我们对版本 JSON 与 JVM 参数的危险参数过滤（可注入任意
	// javaagent / 本地代理）。这里显式下发净化后的环境，只剥掉这一族变量。
	gameEnv, strippedEnv := currentGameEnvironment(nil)
	cmd.Env = gameEnv
	for _, name := range strippedEnv {
		a.writeLog("安全: 已从游戏进程环境中剥离隐式 JVM 参数变量: %s", name)
	}
	// DLL 搜索顺序劫持防护：PATH 只保留系统目录 + Java 目录，剔除用户可写
	// 目录（Downloads / Temp / 网盘同步目录等），防止同名恶意 DLL 被加载进
	// 游戏进程。被剔除条目落审计日志（最多列 10 条，完整计数保留）。
	gameEnv, droppedPath, droppedPathList := sanitizeGameEnv(gameEnv, filepath.Dir(javaPath))
	if droppedPath > 0 {
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionDetected,
			"minecraft", fmt.Sprintf("已从游戏进程 PATH 剔除 %d 个非系统目录（防 DLL 劫持），例: %s",
				droppedPath, strings.Join(droppedPathList, "; ")))
	}
	cmd.Env = gameEnv
	if len(strippedEnv) > 0 {
		// 只记录变量名（值可能含敏感路径/令牌），作为"环境被人动过"的留痕。
		recordSecurityEvent(auditCategoryJVMEnv, auditSeverityWarn, auditActionStripped,
			"minecraft", "启动游戏时剥离隐式 JVM 参数环境变量: "+strings.Join(strippedEnv, ","))
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建 stdout 管道失败: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建 stderr 管道失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动游戏失败: %v", err)
	}
	pid := cmd.Process.Pid
	processStartTime := time.Now()
	a.writeLog("游戏进程 PID: %d", pid)
	a.recordSessionStart(versionID, pid)

	go a.watchGameProcess(cmd, stdoutPipe, stderrPipe, pid, processStartTime, versionID)
	return nil
}
