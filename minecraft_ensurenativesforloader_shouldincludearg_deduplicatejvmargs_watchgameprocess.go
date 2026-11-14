package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) watchGameProcess(cmd *exec.Cmd, stdoutPipe io.Reader, stderrPipe io.Reader, pid int, processStartTime time.Time) {
	runtime.EventsEmit(a.ctx, "launchStatus", "launching")

	crashDetected := false
	crashReason := ""
	windowFound := false
	logProgress := 0 // 日志加载进度 1-5（参考PCL的Watcher）

	// 保存最近的日志行（用于崩溃时显示上下文）
	var recentLines []string
	const maxRecentLines = 50

	// 用 channel 通知进程退出
	exitChan := make(chan int, 1)

	// 用 Wait() 在独立 goroutine 中等待进程退出
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

	// 启动日志监控 goroutine
	logChan := make(chan string, 200)

	// 读取 stdout
	if stdoutPipe != nil {
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				line := scanner.Text()
				logChan <- line
			}
		}()
	}

	// 读取 stderr
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			logChan <- line
		}
	}()

	// 日志分析 goroutine
	go func() {
		for line := range logChan {
			// 保存最近的日志行
			recentLines = append(recentLines, line)
			if len(recentLines) > maxRecentLines {
				recentLines = recentLines[len(recentLines)-maxRecentLines:]
			}

			// 1. 检测崩溃关键字
			for _, keyword := range crashKeywords {
				if strings.Contains(line, keyword) {
					crashDetected = true
					// 收集崩溃上下文
					contextLines := recentLines
					if len(contextLines) > 20 {
						contextLines = contextLines[len(contextLines)-20:]
					}
					crashReason = strings.Join(contextLines, "\n")
					break
				}
			}

			// 2. 检测加载进度（参考PCL的Watcher.GameLog）
			for _, kw := range logProgressKeywords {
				if strings.Contains(line, kw.keyword) && kw.level > logProgress {
					logProgress = kw.level
				}
			}

			// 3. 日志进度5 或窗口出现 = 游戏启动成功
			if logProgress >= 5 && !windowFound {
				windowFound = true
				runtime.EventsEmit(a.ctx, "launchStatus", "success")
			}
		}
	}()

	// 主循环：检测窗口和进程状态
	startTime := time.Now()
	launchTimeout := 30 * time.Second

	for {
		elapsed := time.Since(startTime)

		// 检查窗口是否出现（参考PCL的TryGetMinecraftWindow）
		if !windowFound {
			found, isFML := findMinecraftWindow(pid, processStartTime)
			if found {
				if isFML {
					// FML 窗口：标记窗口已出现但继续等待真正的 MC 窗口
					windowFound = true
					runtime.EventsEmit(a.ctx, "launchStatus", "success")
				} else {
					// 非 FML 窗口：游戏已完全启动
					windowFound = true
					runtime.EventsEmit(a.ctx, "launchStatus", "success")
					// 等待进程退出
					select {
					case exitCode := <-exitChan:
						if exitCode != 0 {
							a.writeLog("!!! 游戏运行中崩溃 (退出码: %d) !!!", exitCode)
							runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
							runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏已退出 (退出码: %d)", exitCode))
						}
						return
					}
					return
				}
			}
		}

		// 检查进程是否已退出（非阻塞）
		select {
		case exitCode := <-exitChan:
			a.writeLog("游戏进程退出，退出码: %d, 运行时间: %.1f秒, 窗口出现: %v", exitCode, time.Since(startTime).Seconds(), windowFound)
			if !windowFound {
				// 收集最近的日志作为错误信息
				logContext := ""
				if len(recentLines) > 0 {
					contextLines := recentLines
					if len(contextLines) > 20 {
						contextLines = contextLines[len(contextLines)-20:]
					}
					logContext = "\n\n最近日志:\n" + strings.Join(contextLines, "\n")
					a.writeLog("最近游戏日志（最后20行）:")
					for _, l := range contextLines {
						a.writeLog("  %s", l)
					}
				}
				if elapsed < 3*time.Second {
					a.writeLog("!!! 游戏启动失败：进程立即退出 (退出码: %d) !!!", exitCode)
					a.writeLog("--- UI 报错内容 ---")
					a.writeLog("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext)
					a.writeLog("--- UI 报错内容结束 ---")
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏启动失败，进程立即退出 (退出码: %d)%s", exitCode, logContext))
				} else {
					a.writeLog("!!! 游戏进程意外退出 (退出码: %d) !!!", exitCode)
					a.writeLog("--- UI 报错内容 ---")
					a.writeLog("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext)
					a.writeLog("--- UI 报错内容结束 ---")
					runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
					runtime.EventsEmit(a.ctx, "crashInfo", fmt.Sprintf("游戏进程意外退出 (退出码: %d)%s", exitCode, logContext))
				}
			}
			return
		default:
		}

		// 检查是否崩溃（通过日志关键字）
		if crashDetected && !windowFound {
			select {
			case <-exitChan:
			case <-time.After(5 * time.Second):
			}
			a.writeLog("!!! 检测到游戏崩溃 !!!")
			a.writeLog("--- UI 报错内容 ---")
			a.writeLog(crashReason)
			a.writeLog("--- UI 报错内容结束 ---")
			runtime.EventsEmit(a.ctx, "launchStatus", "crashed")
			runtime.EventsEmit(a.ctx, "crashInfo", crashReason)
			return
		}

		// 超时检测
		if elapsed > launchTimeout && !windowFound {
			// 如果有日志进度，说明游戏在加载中，延长超时
			if logProgress >= 2 {
				// 再等30秒
				if elapsed > 60*time.Second {
					runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
					return
				}
			} else {
				runtime.EventsEmit(a.ctx, "launchStatus", "timeout")
				return
			}
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// findMinecraftWindow 查找 Minecraft 游戏窗口（参考PCL的TryGetMinecraftWindow三重过滤条件）
// 返回 (是否找到, 是否为FML窗口)
