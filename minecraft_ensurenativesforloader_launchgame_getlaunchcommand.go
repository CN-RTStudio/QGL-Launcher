package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

)

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
