package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) LaunchGame(versionID string) error {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 设置启动日志路径（版本目录下的 QGL\Logs\qgl_launch.log）
	a.launchLogPath = filepath.Join(versionDir, "QGL", "Logs", "qgl_launch.log")
	a.writeLog("===== 启动游戏: %s =====", versionID)
	a.writeLog("版本目录: %s", versionDir)
	a.writeLog("启动日志: %s", a.launchLogPath)

	// 1. 解析版本 JSON（处理 inheritsFrom 继承关系）
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 判断是否为旧版 JSON（使用 minecraftArguments 而非 arguments）
	isOldJSON := versionJSON.MinecraftArgs != ""

	// 2. 选择合适的 Java（根据 MC 版本自动匹配）
	javaEntry, err := a.SelectJavaForVersion(versionID)
	if err != nil {
		return fmt.Errorf("Java 选择失败: %v", err)
	}
	javaPath := javaEntry.Path

	// 3. 确定游戏目录（版本隔离）
	var gameDir string
	if a.isVersionIsolated() {
		gameDir = versionDir
	} else {
		gameDir = mcDir
	}

	// 4. 确保游戏目录存在
	if err := os.MkdirAll(gameDir, 0755); err != nil {
		return fmt.Errorf("创建游戏目录失败: %v", err)
	}

	// 5. 补全缺失的库文件（参考 PCL 的 DlClientFix）
	runtime.EventsEmit(a.ctx, "launchStatus", "fixing")
	a.emitProgress("downloading", "补全文件中", 0, 0)
	a.fixMissingLibraries(mcDir, versionJSON)

	// 6. 提取 natives（从合并后的完整 libraries 列表中提取）
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		return fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)

	// 6.5 如果 natives 目录为空（加载器版本的原版 natives 在父版本目录中），
	// 尝试从父版本的 natives 目录复制或重新解压
	if isEmpty, _ := isDirEmpty(nativesDir); isEmpty {
		a.writeLog("警告: natives 目录为空，尝试从父版本或原版复制: %s", nativesDir)
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	// 7. 构建类路径
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	// 7.1 Forge 1.17+ 特殊处理：从 classpath 中移除 minecraft.jar
	// 原因：Forge 1.17+ 使用 BootstrapLauncher + ALL-MODULE-PATH，
	//        如果 minecraft.jar 在 classpath 中，JVM 会把它加载为模块 minecraft，
	//        与 Forge 的模块 _1._19._2 冲突（两者导出相同的包 → ResolutionException）
	//        BootstrapLauncher 会通过 -DignoreList 和自己的机制加载 minecraft.jar
	// 参考 PCL：PCL 使用 -jar JavaWrapper.jar 启动，-cp 被忽略，所以不受此影响
	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) &&
		javaEntry.MajorVer >= 17
	if isForgeNew {
		// 从 classpathEntries 中移除 minecraft.jar（原版 jar）
		var filteredEntries []string
		for _, entry := range classpathEntries {
			// 检查是否是原版 jar（路径中包含 versions/1.19.2/1.19.2.jar 这样的模式）
			if strings.Contains(entry, "versions") && strings.HasSuffix(entry, ".jar") {
				// 提取 jar 文件名，检查是否是原版 jar（不包含 forge/fabric 等字样）
				jarBase := filepath.Base(entry)
				jarNameNoExt := strings.TrimSuffix(jarBase, ".jar")
				// 如果 jar 名字不包含 forge/fabric/neoforge，说明是原版 jar
				if !strings.Contains(strings.ToLower(jarNameNoExt), "forge") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "fabric") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "neoforge") &&
					!strings.Contains(strings.ToLower(jarNameNoExt), "quilt") {
					a.writeLog("Forge 1.17+ 模块冲突修复: 从 classpath 移除原版 jar: %s", entry)
					continue
				}
			}
			filteredEntries = append(filteredEntries, entry)
		}
		classpathEntries = filteredEntries
	}

	classpath := strings.Join(classpathEntries, ";")

	// 7.5 Fabric 特殊处理：设置 fabric.classPathGroups 系统属性
	// KnotClassLoader 需要此属性来正确加载 jline 等库，否则报 NoClassDefFoundError
	// 格式参考 Fabric 源码: "groupName:file://path1;file://path2"
	isFabric := strings.Contains(versionID, "fabric") ||
		strings.Contains(versionJSON.MainClass, "fabricmc") ||
		strings.Contains(versionJSON.MainClass, "knot")
	var fabricClassPathGroups string
	if isFabric && len(classpathEntries) > 0 {
		// 将每个 classpath 条目加上 file:// 前缀，用分号分隔（Fabric KnotClassLoader 期望的格式）
		var formattedPaths []string
		for _, p := range classpathEntries {
			formattedPaths = append(formattedPaths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		fabricClassPathGroups = "default:" + strings.Join(formattedPaths, ";")
		a.writeLog("检测到 Fabric 版本，设置 fabric.classPathGroups (%d 个库)", len(classpathEntries))
	}

	maxMem := "2G"
	minMem := "1G"
	config, _ := a.GetGlobalConfig()
	if config != nil {
		if config.MaxMemory > 0 {
			maxMem = fmt.Sprintf("%dG", config.MaxMemory)
		}
		if config.MinMemory > 0 {
			minMem = fmt.Sprintf("%dG", config.MinMemory)
		}
	}

	var jvmArgs []string

	if isOldJSON {
		// 旧版（< 1.13）：手动拼接固定 JVM 参数模板（参考PCL的McLaunchArgumentsJvmOld）
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions",
			"-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20",
			"-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50",
			"-XX:G1HeapRegionSize=32M",
		}
	} else {
		// 新版（>= 1.13）：从 arguments.jvm 数组解析
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
			"-Dorg.lwjgl.util.Debug=true",
		}

		if versionJSON.Arguments != nil && len(versionJSON.Arguments.JVM) > 0 {
			for _, arg := range versionJSON.Arguments.JVM {
				switch v := arg.(type) {
				case string:
					// 替换变量
					resolved := v
					resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
					resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
					resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
					resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
					resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
					resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
					jvmArgs = append(jvmArgs, resolved)
				case map[string]interface{}:
					// 带 rules 的参数，检查是否适用
					if shouldIncludeArg(v) {
						if values, ok := v["value"]; ok {
							switch val := values.(type) {
							case string:
								resolved := val
								resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
								resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
								resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
								resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
								resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
								resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
								jvmArgs = append(jvmArgs, resolved)
							case []interface{}:
								for _, item := range val {
									if s, ok := item.(string); ok {
										resolved := s
										resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
										resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
										resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
										resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
										resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
										resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
										jvmArgs = append(jvmArgs, resolved)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 7.6 Fabric: 添加 fabric.classPathGroups 系统属性（必须在 jvmArgs 构建之后）
	if isFabric && fabricClassPathGroups != "" {
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups="+fabricClassPathGroups)
	}

	// 7.7 Forge 特殊处理：移除我们之前添加的 --add-exports bootstraplauncher 参数
	// 问题：--add-exports 在模块加载前被处理，导致 "Unknown module" 警告
	// BootstrapLauncher 会自己处理模块加载，不需要提前添加此参数

	// 7.8 恢复原始的 ALL-MODULE-PATH 行为，不移除也不添加 --limit-modules
	// BootstrapLauncher 会正确处理模块依赖，不需要我们干预

	// 7.9 JVM 参数去重（参考 PCL 的 DeDuplicateDataList 逻辑）
	// 如果不合并多词参数（如 -XX:MaxDirectMemorySize 256M）就去重，
	// 会导致 Forge 1.17+ 启动无效（它有两个 --add-exports，其中一个会在去重时丢失）
	jvmArgs = deduplicateJvmArgs(jvmArgs)

	// 8. 构建游戏参数
	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	userID := currentUser.Dir

	// 根据用户类型确定 UUID、access token 和 user type
	uuid := generateOfflineUUID(username)
	// 离线用户 AccessToken = UUID（参考PCL的McLoginLegacyStart，避免Demo模式）
	accessToken := uuid
	// PCL 对所有用户类型都使用 "msa" 作为 user_type，避免Demo模式
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(userID)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(userID)
			authData, authErr = a.GetMSAuthData(userID)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(userID)
			extData, extErr = a.GetExternalAuthData(userID)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
				// 外置用户仍使用 "msa" 作为 user_type，避免 Demo 模式
				// authlib-injector 会拦截 Mojang authlib 调用并重定向到 Yggdrasil 服务器
			}
		}
	}

	assetsRoot := filepath.Join(mcDir, "assets")
	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}

	// 旧版资源路径（1.6 以下使用 game_assets 而非 assets_root）
	gameAssets := filepath.Join(mcDir, "assets", "virtual", "legacy")

	replacements := map[string]string{
		"${auth_player_name}":  username,
		"${version_name}":      versionID,
		"${game_directory}":    gameDir,
		"${assets_root}":       assetsRoot,
		"${assets_index_name}": assetIndexName,
		"${auth_uuid}":         uuid,
		"${auth_access_token}": accessToken,
		"${access_token}":      accessToken,
		"${auth_session}":      accessToken,
		"${user_type}":         userType,
		"${version_type}":      "QGL",
		"${user_properties}":   "{}",
		"${game_assets}":       gameAssets,
		"${classpath}":         classpath,
		"${classpath_separator}": ";",
		"${natives_directory}": nativesDir,
		"${library_directory}": filepath.Join(mcDir, "libraries"),
		"${launcher_name}":     "QGL",
		"${launcher_version}": launcherVersion,
		"${resolution_width}":  "854",
		"${resolution_height}": "480",
	}

	var gameArgs []string

	// 旧版 Game 参数：从 minecraftArguments 字段解析（参考PCL的McLaunchArgumentsGameOld）
	if isOldJSON {
		parts := strings.Split(versionJSON.MinecraftArgs, " ")
		for _, part := range parts {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
		// 旧版如果没有 --height 和 --width，追加默认分辨率
		hasHeight := false
		for _, a := range gameArgs {
			if a == "--height" || strings.HasPrefix(a, "--height=") {
				hasHeight = true
				break
			}
		}
		if !hasHeight {
			gameArgs = append(gameArgs, "--height", "480", "--width", "854")
		}
	}

	// 新版 Game 参数：从 arguments.game 数组解析（参考PCL的McLaunchArgumentsGameNew）
	// 注意：minecraftArguments 和 arguments.game 可以共存，两者拼接
	if versionJSON.Arguments != nil && len(versionJSON.Arguments.Game) > 0 {
		for _, arg := range versionJSON.Arguments.Game {
			switch v := arg.(type) {
			case string:
				resolved := v
				for k, rep := range replacements {
					resolved = strings.ReplaceAll(resolved, k, rep)
				}
				gameArgs = append(gameArgs, resolved)
			case map[string]interface{}:
				if shouldIncludeArg(v) {
					if values, ok := v["value"]; ok {
						switch val := values.(type) {
						case string:
							resolved := val
							for k, rep := range replacements {
								resolved = strings.ReplaceAll(resolved, k, rep)
							}
							gameArgs = append(gameArgs, resolved)
						case []interface{}:
							for _, item := range val {
								if s, ok := item.(string); ok {
									resolved := s
									for k, rep := range replacements {
										resolved = strings.ReplaceAll(resolved, k, rep)
									}
									gameArgs = append(gameArgs, resolved)
								}
							}
						}
					}
				}
			}
		}
	}

	// 8. 组装完整命令
	mainClass := versionJSON.MainClass
	if mainClass == "" {
		return fmt.Errorf("版本 JSON 中缺少 mainClass")
	}

	// 外置用户：注入 authlib-injector
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr != nil {
			a.writeLog("警告: 读取外置认证数据失败: %v", extErr)
		} else {
			injectorPath, injErr := a.GetAuthlibInjectorPath()
			if injErr != nil {
				a.writeLog("错误: 获取 authlib-injector 失败: %v", injErr)
				return fmt.Errorf("外置登录需要 authlib-injector，但获取失败: %v", injErr)
			}
			// 将 authlib-injector.jar 加入 classpath（关键！否则仍使用 Mojang 原版 authlib）
			classpath = injectorPath + ";" + classpath
			a.writeLog("authlib-injector 路径: %s", injectorPath)

			// 预获取服务器信息（参考 PCL 的 prefetched 机制）
			serverURL := extData.ServerURL
			prefetched := ""
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get(serverURL)
			if err == nil {
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				prefetched = base64.StdEncoding.EncodeToString(respBody)
				a.writeLog("预获取服务器信息成功，长度: %d", len(respBody))
			} else {
				a.writeLog("警告: 预获取服务器信息失败: %v", err)
			}

			injectorArgs := []string{
				"-javaagent:" + injectorPath + "=" + serverURL,
				"-Dauthlibinjector.side=client",
			}
			if prefetched != "" {
				injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
			}
			// 插入到 jvmArgs 最前面
			jvmArgs = append(injectorArgs, jvmArgs...)
			a.writeLog("已注入 authlib-injector 参数: %v", injectorArgs)
		}
	}

	// 检查 jvmArgs 中是否已包含 -cp（新版 Forge/Fabric 的 JSON 中自带 -cp ${classpath}）
	hasCpInJvmArgs := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCpInJvmArgs = true
			break
		}
	}

	var allArgs []string
	if hasCpInJvmArgs {
		// 新版 JSON 已包含 -cp，直接追加 mainClass 和 gameArgs
		allArgs = append(jvmArgs, mainClass)
		allArgs = append(allArgs, gameArgs...)
	} else {
		// 旧版 JSON 没有 -cp，需要手动添加
		allArgs = append(jvmArgs, "-cp", classpath, mainClass)
		allArgs = append(allArgs, gameArgs...)
	}

	// 打印完整命令行到日志文件（用于调试对比 PCL）
	a.writeLog("===== 完整启动命令 =====")
	a.writeLog("Java: %s", javaPath)
	a.writeLog("工作目录: %s", gameDir)
	a.writeLog("JVM 参数数: %d, Classpath 条目数: %d, 游戏参数数: %d, 总参数数: %d",
		len(jvmArgs), len(classpathEntries), len(gameArgs), len(allArgs))
	for i, arg := range allArgs {
		if len(arg) > 150 {
			a.writeLog("  [%d] %s...", i, arg[:150])
		} else {
			a.writeLog("  [%d] %s", i, arg)
		}
	}
	a.writeLog("========================")

	// 8.5 设置游戏语言为中文（参考 PCL 的 options.txt 修改逻辑）
	a.setGameLanguage(gameDir, versionID)

	// 9. 执行命令
	// 使用 SysProcAttr.CmdLine 直接传递原始命令行给 CreateProcess，
	// 避免 Go 的 makeCmdLine 参数解析问题，同时 Go 仍能直接追踪 Java 进程
	var cmdLineParts []string
	cmdLineParts = append(cmdLineParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") {
			cmdLineParts = append(cmdLineParts, "\""+arg+"\"")
		} else {
			cmdLineParts = append(cmdLineParts, arg)
		}
	}
	fullCmdLine := strings.Join(cmdLineParts, " ")
	a.writeLog("命令行长度: %d 字符", len(fullCmdLine))

	cmd := exec.Command(javaPath)
	cmd.Dir = gameDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fullCmdLine,
	}

	// 创建管道捕获 stdout 和 stderr
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

	// 10. 在后台监控游戏状态
	go a.watchGameProcess(cmd, stdoutPipe, stderrPipe, pid, processStartTime)

	return nil
}

// GetLaunchCommand 获取启动命令（不执行），用于导出启动命令功能
func (a *App) GetLaunchCommand(versionID string) (string, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 1. 解析版本 JSON
	versionJSON, err := a.resolveVersionJSON(versionID)
	if err != nil {
		return "", fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	isOldJSON := versionJSON.MinecraftArgs != ""

	// 2. 选择 Java
	javaEntry, err := a.SelectJavaForVersion(versionID)
	if err != nil {
		return "", fmt.Errorf("Java 选择失败: %v", err)
	}
	javaPath := javaEntry.Path

	// 3. 确定游戏目录
	var gameDir string
	if a.isVersionIsolated() {
		gameDir = versionDir
	} else {
		gameDir = mcDir
	}

	// 5. 补全缺失的库文件
	a.fixMissingLibraries(mcDir, versionJSON)

	// 6. 提取 natives
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	if err := os.MkdirAll(nativesDir, 0755); err != nil {
		return "", fmt.Errorf("创建 natives 目录失败: %v", err)
	}
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)

	if isEmpty, _ := isDirEmpty(nativesDir); isEmpty {
		a.ensureNativesForLoader(mcDir, versionID, versionDir, nativesDir, versionJSON)
	}

	// 7. 构建类路径
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) &&
		javaEntry.MajorVer >= 17
	if isForgeNew {
		var filteredEntries []string
		for _, entry := range classpathEntries {
			jarBase := filepath.Base(entry)
			jarNameNoExt := strings.TrimSuffix(jarBase, ".jar")
			if !strings.Contains(strings.ToLower(jarNameNoExt), "forge") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "fabric") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "neoforge") &&
				!strings.Contains(strings.ToLower(jarNameNoExt), "quilt") {
				continue
			}
			filteredEntries = append(filteredEntries, entry)
		}
		classpathEntries = filteredEntries
	}

	classpath := strings.Join(classpathEntries, ";")

	isFabric := strings.Contains(versionID, "fabric") ||
		strings.Contains(versionJSON.MainClass, "fabricmc") ||
		strings.Contains(versionJSON.MainClass, "knot")
	var fabricClassPathGroups string
	if isFabric && len(classpathEntries) > 0 {
		var formattedPaths []string
		for _, p := range classpathEntries {
			formattedPaths = append(formattedPaths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		fabricClassPathGroups = "default:" + strings.Join(formattedPaths, ";")
	}

	maxMem := "2G"
	minMem := "1G"
	config, _ := a.GetGlobalConfig()
	if config != nil {
		if config.MaxMemory > 0 {
			maxMem = fmt.Sprintf("%dG", config.MaxMemory)
		}
		if config.MinMemory > 0 {
			minMem = fmt.Sprintf("%dG", config.MinMemory)
		}
	}

	var jvmArgs []string

	if isOldJSON {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions",
			"-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20",
			"-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50",
			"-XX:G1HeapRegionSize=32M",
		}
	} else {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem),
			fmt.Sprintf("-Xms%s", minMem),
			"-Dlog4j2.formatMsgNoLookups=true",
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
			"-Dorg.lwjgl.util.Debug=true",
		}

		if versionJSON.Arguments != nil && len(versionJSON.Arguments.JVM) > 0 {
			for _, arg := range versionJSON.Arguments.JVM {
				switch v := arg.(type) {
				case string:
					resolved := v
					resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
					resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
					resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
					resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
					resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
					resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
					resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
					jvmArgs = append(jvmArgs, resolved)
				case map[string]interface{}:
					if shouldIncludeArg(v) {
						if values, ok := v["value"]; ok {
							switch val := values.(type) {
							case string:
								resolved := val
								resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
								resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
								resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
								resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
								resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
								resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
								resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
								jvmArgs = append(jvmArgs, resolved)
							case []interface{}:
								for _, item := range val {
									if s, ok := item.(string); ok {
										resolved := s
										resolved = strings.ReplaceAll(resolved, "${natives_directory}", nativesDir)
										resolved = strings.ReplaceAll(resolved, "${library_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${libraries_directory}", filepath.Join(mcDir, "libraries"))
										resolved = strings.ReplaceAll(resolved, "${classpath_separator}", ";")
										resolved = strings.ReplaceAll(resolved, "${classpath}", classpath)
										resolved = strings.ReplaceAll(resolved, "${launcher_name}", "QGL")
										resolved = strings.ReplaceAll(resolved, "${launcher_version}", launcherVersion)
										resolved = strings.ReplaceAll(resolved, "${version_name}", versionID)
										jvmArgs = append(jvmArgs, resolved)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if isFabric && fabricClassPathGroups != "" {
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups="+fabricClassPathGroups)
	}

	jvmArgs = deduplicateJvmArgs(jvmArgs)

	// 8. 构建游戏参数
	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	userID := currentUser.Dir

	uuid := generateOfflineUUID(username)
	accessToken := uuid
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(userID)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(userID)
			authData, authErr = a.GetMSAuthData(userID)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(userID)
			extData, extErr = a.GetExternalAuthData(userID)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s",
						uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
				// 外置用户仍使用 "msa" 作为 user_type，避免 Demo 模式
				// authlib-injector 会拦截 Mojang authlib 调用并重定向到 Yggdrasil 服务器
			}
		}
	}

	assetsRoot := filepath.Join(mcDir, "assets")
	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}

	gameAssets := filepath.Join(mcDir, "assets", "virtual", "legacy")

	replacements := map[string]string{
		"${auth_player_name}":    username,
		"${version_name}":        versionID,
		"${game_directory}":      gameDir,
		"${assets_root}":         assetsRoot,
		"${assets_index_name}":   assetIndexName,
		"${auth_uuid}":           uuid,
		"${auth_access_token}":   accessToken,
		"${access_token}":        accessToken,
		"${auth_session}":        accessToken,
		"${user_type}":           userType,
		"${version_type}":        "QGL",
		"${user_properties}":     "{}",
		"${game_assets}":         gameAssets,
		"${classpath}":           classpath,
		"${classpath_separator}": ";",
		"${natives_directory}":   nativesDir,
		"${library_directory}":   filepath.Join(mcDir, "libraries"),
		"${launcher_name}":       "QGL",
		"${launcher_version}": launcherVersion,
		"${resolution_width}":    "854",
		"${resolution_height}":   "480",
	}

	var gameArgs []string

	if isOldJSON {
		parts := strings.Split(versionJSON.MinecraftArgs, " ")
		for _, part := range parts {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
		hasHeight := false
		for _, a := range gameArgs {
			if a == "--height" || strings.HasPrefix(a, "--height=") {
				hasHeight = true
				break
			}
		}
		if !hasHeight {
			gameArgs = append(gameArgs, "--height", "480", "--width", "854")
		}
	}

	if versionJSON.Arguments != nil && len(versionJSON.Arguments.Game) > 0 {
		for _, arg := range versionJSON.Arguments.Game {
			switch v := arg.(type) {
			case string:
				resolved := v
				for k, rep := range replacements {
					resolved = strings.ReplaceAll(resolved, k, rep)
				}
				gameArgs = append(gameArgs, resolved)
			case map[string]interface{}:
				if shouldIncludeArg(v) {
					if values, ok := v["value"]; ok {
						switch val := values.(type) {
						case string:
							resolved := val
							for k, rep := range replacements {
								resolved = strings.ReplaceAll(resolved, k, rep)
							}
							gameArgs = append(gameArgs, resolved)
						case []interface{}:
							for _, item := range val {
								if s, ok := item.(string); ok {
									resolved := s
									for k, rep := range replacements {
										resolved = strings.ReplaceAll(resolved, k, rep)
									}
									gameArgs = append(gameArgs, resolved)
								}
							}
						}
					}
				}
			}
		}
	}

	mainClass := versionJSON.MainClass
	if mainClass == "" {
		return "", fmt.Errorf("版本 JSON 中缺少 mainClass")
	}

	// 外置用户：注入 authlib-injector
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(userID)
		if extErr != nil {
			return "", fmt.Errorf("读取外置认证数据失败: %v", extErr)
		}
		injectorPath, injErr := a.GetAuthlibInjectorPath()
		if injErr != nil {
			return "", fmt.Errorf("外置登录需要 authlib-injector，但获取失败: %v", injErr)
		}
		// 将 authlib-injector.jar 加入 classpath
		classpath = injectorPath + ";" + classpath

		serverURL := extData.ServerURL
		prefetched := ""
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(serverURL)
		if err == nil {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			prefetched = base64.StdEncoding.EncodeToString(respBody)
		}

		injectorArgs := []string{
			"-javaagent:" + injectorPath + "=" + serverURL,
			"-Dauthlibinjector.side=client",
		}
		if prefetched != "" {
			injectorArgs = append(injectorArgs, "-Dauthlibinjector.yggdrasil.prefetched="+prefetched)
		}
		jvmArgs = append(injectorArgs, jvmArgs...)
	}

	hasCpInJvmArgs := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCpInJvmArgs = true
			break
		}
	}

	var allArgs []string
	if hasCpInJvmArgs {
		allArgs = append(jvmArgs, mainClass)
		allArgs = append(allArgs, gameArgs...)
	} else {
		allArgs = append(jvmArgs, "-cp", classpath, mainClass)
		allArgs = append(allArgs, gameArgs...)
	}

	// 组装完整命令字符串
	var cmdParts []string
	cmdParts = append(cmdParts, "\""+javaPath+"\"")
	for _, arg := range allArgs {
		if strings.Contains(arg, " ") || strings.Contains(arg, "\"") {
			cmdParts = append(cmdParts, "\""+strings.ReplaceAll(arg, "\"", "\\\"")+"\"")
		} else {
			cmdParts = append(cmdParts, arg)
		}
	}

	return strings.Join(cmdParts, " "), nil
}

// shouldIncludeArg 检查带 rules 的参数是否应该包含（参考PCL的McJsonRuleCheck）
