package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) ensureNativesForLoader(mcDir string, versionID string, versionDir string, nativesDir string, versionJSON *VersionJSON) {
	// 策略1: 从父版本（原版 MC）的 natives 目录复制
	if versionJSON.InheritsFrom != "" {
		parentNativesDir := filepath.Join(mcDir, "versions", versionJSON.InheritsFrom, versionJSON.InheritsFrom+"-natives")
		if entries, err := os.ReadDir(parentNativesDir); err == nil && len(entries) > 0 {
			fmt.Printf("从父版本复制 natives: %s -> %s\n", parentNativesDir, nativesDir)
			copyDirContents(parentNativesDir, nativesDir)
			return
		}
	}

	// 策略2: 尝试从其他已安装版本中查找匹配的原版 natives
	versionsDir := filepath.Join(mcDir, "versions")
	entries, _ := os.ReadDir(versionsDir)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidateNatives := filepath.Join(versionsDir, entry.Name(), entry.Name()+"-natives")
		if info, err := os.Stat(candidateNatives); err == nil && info.IsDir() {
			if subEntries, err2 := os.ReadDir(candidateNatives); err2 == nil && len(subEntries) > 0 {
				fmt.Printf("从 %s 复制 natives 到 %s\n", candidateNatives, nativesDir)
				copyDirContents(candidateNatives, nativesDir)
				return
			}
		}
	}

	// 策略3: 强制重新解压（合并后的 JSON 应该包含 native 库信息）
	fmt.Printf("尝试重新解压 natives 到: %s\n", nativesDir)
	a.extractNativesFromJSON(mcDir, nativesDir, versionJSON)
}

// copyDirContents 复制目录中的所有文件到目标目录
func copyDirContents(srcDir string, dstDir string) error {
	os.MkdirAll(dstDir, 0755)

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		data, err := os.ReadFile(srcPath)
		if err != nil {
			continue
		}
		os.WriteFile(dstPath, data, 0644)
	}

	return nil
}

// generateOfflineUUID 根据用户名生成离线 UUID
func generateOfflineUUID(username string) string {
	data := "OfflinePlayer:" + username
	hash := md5.Sum([]byte(data))

	hash[6] = (hash[6] & 0x0f) | 0x30
	hash[8] = (hash[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// generateRandomToken 生成随机访问令牌（避免Demo模式）
func generateRandomToken() string {
	now := time.Now().UnixNano()
	data := fmt.Sprintf("QGLToken%d%d", now, os.Getpid())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// 崩溃检测关键字（参考PCL）
var crashKeywords = []string{
	"Crash report saved to",
	"This crash report has been saved to:",
	"Could not save crash report to",
	"Someone is closing me!",
	"Restarting Minecraft with command",
	"An exception was thrown, the game will display an error screen and halt.",
	"UNABLE TO LAUNCH",
	"Failed to start the Minecraft runtime",
	"Exception in thread",
	"java.lang.UnsatisfiedLinkError",
	"java.lang.NoClassDefFoundError",
	"java.lang.OutOfMemoryError",
	"Unable to launch",
	"java.lang.reflect.InvocationTargetException",
}

// 日志进度关键字（参考PCL的Watcher）
var logProgressKeywords = []struct {
	level  int
	keyword string
}{
	{2, "Setting user:"},
	{3, "LWJGL Version:"},
	{3, "lwjgl version"},
	{4, "OpenAL initialized"},
	{4, "Starting up SoundSystem"},
	{5, "Created: "},
	{5, "textures"},
	{5, "-atlas"},
}

// LaunchGame 启动 Minecraft 游戏，并检测窗口出现或崩溃
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
func (a *App) isVersionIsolated() bool {
	return a.IsVersionIsolation()
}

// buildClasspath 构建类路径（参考 PCL 的 McLibListGetWithJson + McLaunchArgumentsReplace）
func (a *App) buildClasspath(mcDir string, versionID string, versionJSON *VersionJSON) []string {
	var classpathEntries []string
	libsDir := filepath.Join(mcDir, "libraries")

	for _, lib := range versionJSON.Libraries {
		// 1. 检查 rules（跳过不适用于当前平台的库）
		if !a.shouldIncludeLib(lib) {
			continue
		}

		// 2. 跳过 natives 库（natives 不加入 classpath）
		if lib.Natives != nil {
			continue
		}

		// 3. 确定库文件路径
		var libPath string

		// 优先使用 downloads.artifact.path
		if lib.Downloads != nil && lib.Downloads.Artifact != nil && lib.Downloads.Artifact.Path != "" {
			libPath = filepath.Join(libsDir, lib.Downloads.Artifact.Path)
		} else if lib.JarPath != "" {
			// 有些库直接提供 path 字段
			libPath = filepath.Join(libsDir, lib.JarPath)
		} else if lib.Name != "" {
			// 从 Maven 坐标推算路径（参考 PCL 的 McLibGet）
			libPath = mavenNameToPath(lib.Name, libsDir)
		}

		if libPath == "" {
			continue
		}

		// 4. 检查文件是否存在
		if _, err := os.Stat(libPath); err != nil {
			fmt.Printf("类路径库文件不存在(跳过): %s\n", libPath)
			continue
		}
		classpathEntries = append(classpathEntries, libPath)
	}

	// 5. 添加游戏主 jar（classpath 的最后一个条目）
	// 参考 PCL 的 McLibListGet：jar 字段优先，否则沿 inheritsFrom 链查找原版
	jarName := versionJSON.Jar
	if jarName == "" {
		// 沿 inheritsFrom 链查找原版版本名
		jarName = versionJSON.InheritsFrom
	}
	if jarName == "" {
		jarName = versionID
	}
	versionJar := filepath.Join(mcDir, "versions", jarName, jarName+".jar")

	// 如果 jar 不存在，尝试在当前版本目录中查找
	if _, err := os.Stat(versionJar); err != nil {
		altJar := filepath.Join(mcDir, "versions", versionID, versionID+".jar")
		if _, err2 := os.Stat(altJar); err2 == nil {
			versionJar = altJar
		}
	}

	classpathEntries = append(classpathEntries, versionJar)

	return classpathEntries
}

// shouldIncludeLib 检查库是否应该包含（参考 PCL 的 McJsonRuleCheck）
func (a *App) shouldIncludeLib(lib Library) bool {
	if len(lib.Rules) == 0 {
		return true // 没有 rules，默认包含
	}

	allow := false
	for _, rule := range lib.Rules {
		osMatch := true
		if rule.OS != nil {
			osMatch = rule.OS.Name == "windows"
		}

		if rule.Action == "allow" {
			if osMatch {
				allow = true
			}
		} else if rule.Action == "disallow" {
			if osMatch {
				allow = false
			}
		}
	}

	return allow
}

// libGroupArtifact 从 Maven 坐标中提取 group:artifact（不含版本号）
// 例如 "org.apache.logging.log4j:log4j-core:2.17.1" -> "org.apache.logging.log4j:log4j-core"
func libGroupArtifact(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}
	return name
}

// mavenNameToPath 从 Maven 坐标推算库文件路径（参考 PCL 的 McLibGet）
// Maven 坐标格式: group:artifact:version 或 group:artifact:version:classifier
// 路径格式: group/artifact/version/artifact-version(-classifier).jar
func mavenNameToPath(name string, libsDir string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", string(os.PathSeparator))
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	// 文件名: artifact-version(-classifier).jar
	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)

	// 完整路径: libsDir/group/artifact/version/fileName
	return filepath.Join(libsDir, group, artifact, version, fileName)
}

// resolveVersionJSON 解析版本 JSON，处理 inheritsFrom 继承关系
// Forge/Fabric/NeoForge/OptiFine 版本都通过 inheritsFrom 引用原版版本
// 需要合并父版本的 libraries、downloads、assetIndex 等信息
func (a *App) resolveVersionJSON(versionID string) (*VersionJSON, error) {
	mcDir := a.getMinecraftDir()
	versionDir := filepath.Join(mcDir, "versions", versionID)

	// 查找版本 JSON 文件（文件名可能与文件夹名不同）
	jsonPath := filepath.Join(versionDir, versionID+".json")
	if _, err := os.Stat(jsonPath); err != nil {
		// 尝试查找文件夹中的任意 JSON 文件
		jsonFiles, _ := filepath.Glob(filepath.Join(versionDir, "*.json"))
		if len(jsonFiles) > 0 {
			jsonPath = jsonFiles[0]
		} else {
			return nil, fmt.Errorf("未找到版本 JSON: %s", versionDir)
		}
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("读取版本 JSON 失败: %v", err)
	}

	var versionJSON VersionJSON
	if err := json.Unmarshal(jsonData, &versionJSON); err != nil {
		return nil, fmt.Errorf("解析版本 JSON 失败: %v", err)
	}

	// 处理 inheritsFrom
	if versionJSON.InheritsFrom != "" {
		parentJSON, err := a.resolveVersionJSON(versionJSON.InheritsFrom)
		if err != nil {
			fmt.Printf("解析父版本 JSON 失败: %v（将继续使用当前版本信息）\n", err)
		} else {
			// 合并父版本信息
			versionJSON = a.mergeVersionJSON(parentJSON, &versionJSON)
		}
	}

	return &versionJSON, nil
}

// mergeVersionJSON 合并父版本和子版本 JSON
// 子版本（Forge/Fabric）的字段覆盖父版本（原版）的字段
func (a *App) mergeVersionJSON(parent *VersionJSON, child *VersionJSON) VersionJSON {
	merged := *parent // 以父版本为基础

	// 子版本覆盖的字段
	if child.ID != "" {
		merged.ID = child.ID
	}
	if child.MainClass != "" {
		merged.MainClass = child.MainClass
	}
	if child.Type != "" {
		merged.Type = child.Type
	}
	if child.ReleaseTime != "" {
		merged.ReleaseTime = child.ReleaseTime
	}
	if child.Jar != "" {
		merged.Jar = child.Jar
	}

	// 合并 libraries：父版本 + 子版本（按 group:artifact 去重）
	// 规则：子版本的库覆盖父版本中相同 group:artifact 的所有条目
	// 这样 Forge 的 log4j 会覆盖原版的 log4j，而 LWJGL 等原版独有库全部保留
	childGroupArtifacts := map[string]bool{}
	for _, lib := range child.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" {
			childGroupArtifacts[ga] = true
		}
	}
	var mergedLibs []Library
	for _, lib := range parent.Libraries {
		ga := libGroupArtifact(lib.Name)
		if ga != "" && childGroupArtifacts[ga] {
			continue // 子版本有同名 group:artifact，跳过父版本
		}
		mergedLibs = append(mergedLibs, lib)
	}
	mergedLibs = append(mergedLibs, child.Libraries...)
	merged.Libraries = mergedLibs

	// 合并 arguments
	if child.MinecraftArgs != "" {
		merged.MinecraftArgs = child.MinecraftArgs
	}
	if child.Arguments != nil {
		if merged.Arguments == nil {
			merged.Arguments = &ArgumentsObj{}
		}
		// 合并 JVM 参数：父版本 + 子版本
		if len(child.Arguments.JVM) > 0 {
			merged.Arguments.JVM = append(merged.Arguments.JVM, child.Arguments.JVM...)
		}
		// 合并 Game 参数：父版本 + 子版本
		if len(child.Arguments.Game) > 0 {
			merged.Arguments.Game = append(merged.Arguments.Game, child.Arguments.Game...)
		}
	}

	// 子版本有自己的 downloads 时覆盖
	if child.Downloads != nil {
		merged.Downloads = child.Downloads
	}
	// 子版本有自己的 assetIndex 时覆盖
	if child.AssetIndex != nil {
		merged.AssetIndex = child.AssetIndex
	}

	// 保留 inheritsFrom 用于参考
	merged.InheritsFrom = child.InheritsFrom

	return merged
}

