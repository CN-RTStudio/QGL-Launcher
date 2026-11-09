package main

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) GetLaunchCommand(versionID string) (string, error) {
	if err := sanitizePathComponent(versionID); err != nil {
		return "", fmt.Errorf("无效的版本ID: %v", err)
	}
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}
	a.fixMissingLibraries(mcDir, versionJSON)
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	// natives 目录由 extractNativesFromJSON 内部统一以 0700 创建/收权。
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
	if empty, _ := isDirEmpty(nativesDir); empty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}
	allArgs, _, _, _ := a.buildLaunchArgs(versionID, versionJSON, mcDir, versionDir)
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	javaPath := javaEntry.Path

	cmdParts := []string{syscall.EscapeArg(javaPath)}
	for _, arg := range allArgs {
		cmdParts = append(cmdParts, syscall.EscapeArg(arg))
	}
	return strings.Join(cmdParts, " "), nil
}

// dumpCrashContext 在判定崩溃后读取“本局”（startTime 之后）新生成的
// crash-reports / hs_err 崩溃产物摘要，追加到崩溃原因；找不到或读取失败都静默
// 退化为原原因，绝不阻塞崩溃上报。gameDir 即游戏进程的工作目录（cmd.Dir）。
func (a *App) dumpCrashContext(reason, gameDir string, startTime time.Time) string {
	// 崩溃上下文统一脱敏（用户目录 / QGL 根 / 游戏目录 / JWT / 长十六进制），
	// 防止 hs_err 里的绝对路径与令牌被贴到论坛或经错误通道外发。
	if gameDir == "" {
		return redactCrashText(reason, a.GetQGLDir(), "", a.currentUsername())
	}
	if s, ok := collectLatestCrashDump(gameDir, startTime); ok {
		extra := renderCrashDumpSummary(s)
		combined := extra
		if reason != "" {
			combined = reason + "\n" + extra
		}
		return redactCrashText(combined, a.GetQGLDir(), gameDir, a.currentUsername())
	}
	return redactCrashText(reason, a.GetQGLDir(), gameDir, a.currentUsername())
}

func (a *App) watchGameProcess(cmd *exec.Cmd, stdoutPipe io.Reader, stderrPipe io.Reader, pid int, processStartTime time.Time, versionID string) {
	// 实例锁在本函数退出（游戏进程结束 / 启动失败 / 超时）时统一释放。
	defer a.releaseInstanceLock(versionID, "")
	// 会话台账结算：无论从哪条路径退出（正常/崩溃/超时/立即退出），都记一条
	// 结局。各 return 前先更新本组变量，defer 在函数尾统一写盘。
	sessionOutcome := SessionOutcomeOk
	sessionExitCode := -1
	sessionDetail := ""
	defer func() {
		a.recordSessionEnd(versionID, pid, sessionExitCode, sessionOutcome, sessionDetail)
		// 会话日志：函数退出时统一落盘 + 轮转（与台账结算同一时机，避免漏记尾部）。
		a.EndGameSessionLog()
	}()
	// 会话日志：本局日志脱敏持久化从这里开始。
	if err := a.BeginGameSessionLog(versionID); err != nil {
		a.writeLog("会话日志初始化失败: %v", err)
	}
	runtime.EventsEmit(a.ctx, "launchStatus", "launching")
	crashDetected, windowFound := false, false
	crashReason := ""
	logProgress := 0
	var recentLines []string
	exitChan := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		exitCode := -1
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			}
		} else {
			exitCode = 0
		}
		exitChan <- exitCode
	}()
	logChan := make(chan string, 200)
	// 有界流式按行读取：替换默认 bufio.Scanner（单行 64KiB 上限会被超长日志行
	// 静默打断，导致崩溃/进度检测失效；盲目放大缓冲又会被无换行巨行 OOM）。
	// 两个管道都 EOF 后关闭 logChan，让消费 goroutine 能随游戏退出而结束。
	var logWG sync.WaitGroup
	logWG.Add(2)
	pipeGameLog := func(r io.Reader) {
		defer logWG.Done()
		_, truncated, _ := streamBoundedLines(r, maxGameLogLineBytes, func(line string) {
			logChan <- line
		})
		if truncated > 0 {
			recordSecurityEvent("game-log", auditSeverityWarn, auditActionStripped,
				"minecraft", fmt.Sprintf("游戏输出有 %d 行超过 %d 字节单行上限，已截断(防内存膨胀)",
					truncated, maxGameLogLineBytes))
		}
	}
	go pipeGameLog(stdoutPipe)
	go pipeGameLog(stderrPipe)
	go func() {
		logWG.Wait()
		close(logChan)
	}()
	go func() {
		for line := range logChan {
			recentLines = append(recentLines, line)
			if len(recentLines) > 50 {
				recentLines = recentLines[len(recentLines)-50:]
			}
			// 会话日志：脱敏后进环形缓冲，会话结束统一落盘。
			a.AppendGameSessionLine(line)
			for _, kw := range crashKeywords {
				if strings.Contains(line, kw) {
					crashDetected = true
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					crashReason = buildCrashContext(recentLines[start:])
					break
				}
			}
			for _, kw := range logProgressKeywords {
				if strings.Contains(line, kw.keyword) && kw.level > logProgress {
					logProgress = kw.level
				}
			}
			if logProgress >= 5 && !windowFound {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
			}
		}
	}()
	startTime := time.Now()
	launchTimeout := 30 * time.Second
	for {
		elapsed := time.Since(startTime)
		if !windowFound {
			found, _ := findMinecraftWindow(pid, processStartTime)
			if found {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
				select {
				case exitCode := <-exitChan:
					if exitCode != 0 {
						sessionOutcome = SessionOutcomeCrash
						sessionExitCode = exitCode
						runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
						runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏已退出 (退出码: %d)", exitCode))
					} else {
						sessionOutcome = SessionOutcomeOk
						sessionExitCode = 0
					}
				}
				return
			}
		}
		select {
		case exitCode := <-exitChan:
			a.writeLog("游戏进程退出，退出码: %d, 运行时间: %.1f秒", exitCode, elapsed.Seconds())
			if !windowFound {
				logContext := ""
				if len(recentLines) > 0 {
					start := len(recentLines) - 20
					if start < 0 {
						start = 0
					}
					logContext = "\n\n最近日志:\n" + buildCrashContext(recentLines[start:])
				}
				// 控制台没说清真因时，补读本局 crash-reports / hs_err 崩溃产物。
				if dump := a.dumpCrashContext("", cmd.Dir, processStartTime); dump != "" {
					logContext += "\n\n崩溃诊断:\n" + dump
				}
				if elapsed < 3*time.Second {
					sessionOutcome = SessionOutcomeLaunchFail
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext)))
				} else {
					sessionOutcome = SessionOutcomeCrash
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext)))
				}
				sessionExitCode = exitCode
				sessionDetail = logContext
			} else {
				if exitCode != 0 {
					sessionOutcome = SessionOutcomeCrash
				} else {
					sessionOutcome = SessionOutcomeOk
				}
				sessionExitCode = exitCode
			}
			return
		default:
		}
		if crashDetected && !windowFound {
			select {
			case <-exitChan:
			case <-time.After(5 * time.Second):
			}
			crashReason = a.dumpCrashContext(crashReason, cmd.Dir, processStartTime)
			sessionOutcome = SessionOutcomeCrash
			sessionDetail = crashReason
			runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
			runtime.EventsEmit(a.ctx, "crashInfo", sanitizeLogLine(crashReason))
			return
		}
		if elapsed > launchTimeout && !windowFound {
			if logProgress >= 2 && elapsed < 60*time.Second {
				// 继续等待
			} else {
				sessionOutcome = SessionOutcomeTimeout
				runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
