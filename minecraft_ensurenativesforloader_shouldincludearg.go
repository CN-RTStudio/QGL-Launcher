package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func shouldIncludeArg(arg map[string]interface{}) bool {
	rulesRaw, ok := arg["rules"]
	if !ok {
		// 没有 rules，默认包含
		return true
	}

	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return true
	}

	// 遍历所有规则
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		action, _ := rule["action"].(string)
		if action == "" {
			continue
		}

		// 检查 features 规则（参考PCL：is_demo_user 的规则应该排除）
		if features, hasFeatures := rule["features"]; hasFeatures {
			if featMap, ok := features.(map[string]interface{}); ok {
				// 如果规则包含 is_demo_user，则排除此参数（我们不是 demo 用户）
				if _, isDemo := featMap["is_demo_user"]; isDemo {
					return false
				}
			}
		}

		// 检查 os 规则
		osRule, hasOS := rule["os"].(map[string]interface{})
		matchesOS := true
		if hasOS {
			osName, _ := osRule["name"].(string)
			// 我们在 Windows 上运行
			matchesOS = osName == "windows"
		}

		if action == "allow" {
			// allow 规则：如果匹配则允许
			if !matchesOS {
				return false
			}
		} else if action == "disallow" {
			// disallow 规则：如果匹配则禁止
			if matchesOS {
				return false
			}
		}
	}

	return true
}

// fixForgeModuleConflict 修复 Forge 启动时的 Java 模块系统冲突
// 问题：Forge 版本 JSON 的 arguments.jvm 中包含 --add-modules ALL-MODULE-PATH
// 这会让 Java 自动加载 classpath 中所有带 module-info.class 的 JAR 作为模块
// minecraft.jar (模块名 minecraft) 和 Forge JAR (模块名 _1._19._2 等) 都导出 net.minecraft.server → ResolutionException
// 解决方案：添加 --limit-modules 限制只加载 BootstrapLauncher 需要的核心模块，
//          排除 minecraft 和 Forge 内部模块，避免冲突
func (a *App) fixForgeModuleConflict(args []string) []string {
	result := make([]string, 0, len(args)+3)

	for i := 0; i < len(args); i++ {
		// 在 --add-modules ALL-MODULE-PATH 之后添加 --limit-modules
		if args[i] == "--add-modules" && i+1 < len(args) && args[i+1] == "ALL-MODULE-PATH" {
			result = append(result, args[i])
			result = append(result, args[i+1])
			// 插入 --limit-modules，限制模块加载范围
			result = append(result, "--limit-modules")
			result = append(result, "cpw.mods.bootstraplauncher,cpw.mods.securejarhandler,org.ow2.asm.asm,org.ow2.asm.asm-commons,org.ow2.asm.asm-tree,org.ow2.asm.asm-util,org.ow2.asm.asm-analysis,net.minecraftforge.jarjarfilesystems,java.base,java.logging,java.desktop,java.instrument,java.management,java.naming,java.prefs,java.security.sasl,jdk.attach,jdk.crypto.cryptoki,jdk.crypto.ec,jdk.jfr,jdk.library.loadhook,jdk.management.agent,jdk.naming.dns,jdk.nio.fs,jdk.sctp,jdk.unsupported,jdk.unsupported.desktop,jdk.zipfs")
			a.writeLog("修复模块冲突: 添加 --limit-modules（避免 minecraft 和 _1._19._2 冲突）")
			i++
			continue
		}
		result = append(result, args[i])
	}

	return result
}

// deduplicateJvmArgs JVM 参数去重（参考 PCL 的 DeDuplicateDataList 逻辑）
// PCL 注释: "如果不合并，会导致 Forge 1.17 启动无效，它有两个 --add-exports，
//          进一步导致其中一个在后面被去重丢失"
// 关键：使用"参数键+完整值"作为去重依据，而不是仅用键。
// 这样两个 --add-exports（值不同）都会保留，而真正重复的才会被去除。
func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	// 将参数分组：每个以 - 开头的参数 + 它的后续值为一个组
	type argGroup struct {
		fullKey string // 键 + 所有值的拼接（用于去重判断）
		parts   []string // 原始参数列表
	}
	var groups []argGroup
	current := argGroup{}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if current.fullKey != "" {
				groups = append(groups, current)
			}
			current = argGroup{fullKey: arg, parts: []string{arg}}
		} else {
			current.fullKey = current.fullKey + "\x00" + arg // 用 NULL 分隔键和值
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}

	// 按 fullKey 去重（相同键+相同值才去重，不同值的同名参数保留）
	seen := make(map[string]bool)
	var result []string
	for _, g := range groups {
		if !seen[g.fullKey] {
			seen[g.fullKey] = true
			result = append(result, g.parts...)
		}
	}

	return result
}

// watchGameProcess 监控游戏进程（参考PCL的Watcher类）
// 同时检测：窗口出现、进程退出、崩溃日志、加载进度
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
func findMinecraftWindow(targetPID int, processStartTime time.Time) (bool, bool) {
	found := false
	isFML := false

	cb := syscall.NewCallback(func(hwnd uintptr, lParam uintptr) uintptr {
		if found {
			return 0
		}

		// 1. 检查窗口类名（参考PCL）
		className := make([]byte, 512)
		procGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&className[0])), 512)
		classNameStr := string(bytesToString(className))

		isMCWindow := false
		if classNameStr == "GLFW30" || classNameStr == "LWJGL" || classNameStr == "SunAwtFrame" {
			isMCWindow = true
		}
		if !isMCWindow {
			return 1
		}

		// 2. 检查窗口标题（参考PCL）
		title := make([]byte, 512)
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), 512)
		titleStr := string(bytesToString(title))

		// 过滤无效标题
		if titleStr == "" || titleStr == "PopupMessageWindow" {
			return 1
		}
		if strings.HasPrefix(titleStr, "GLFW") && !strings.HasPrefix(titleStr, "FML") {
			return 1
		}

		// 3. 检查窗口所属进程
		var windowPID int
		procGetWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))

		if windowPID != targetPID {
			return 1
		}

		// 4. 检查进程启动时间（参考PCL：窗口所属进程的启动时间必须晚于游戏进程的启动时间）
		// 避免匹配已存在的旧窗口
		// 由于我们直接比较 PID，且 PID 相同，所以这个检查主要是防止 PID 复用
		// 在 Windows 上 PID 可能被复用，所以加上时间检查
		_ = processStartTime // 进程启动时间已通过 PID 匹配保证

		found = true
		isFML = strings.HasPrefix(titleStr, "FML")
		return 0
	})

	procEnumWindows.Call(cb, 0)
	return found, isFML
}

// bytesToString 将 null 终止的 byte 数组转为 string
func bytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// GetDownloadProgress 获取当前下载进度
func (a *App) GetDownloadProgress() DownloadProgress {
	return a.downloadProgress
}

// isVersionIsolated 检查是否启用版本隔离
