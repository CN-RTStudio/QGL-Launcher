package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

func shouldIncludeArg(arg map[string]interface{}) bool {
	// 条件化参数统一走 ruleengine：裸 map 的 rules 被翻译成通用规则后按 Mojang
	// 语义评估（os.name/arch/version + features），与库过滤共用同一内核，避免
	// 两份实现漂移。旧实现只认 windows、且 features 只要出现 is_demo_user 键
	// （无论真假值）就拒绝，会把 {"is_demo_user":false} 的正常参数误删。
	return argumentObjectAllowed(arg, currentRuleEnv())
}

func deduplicateJvmArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	type argGroup struct {
		fullKey string
		parts   []string
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
			current.fullKey = current.fullKey + "\x00" + arg
			current.parts = append(current.parts, arg)
		}
	}
	if current.fullKey != "" {
		groups = append(groups, current)
	}
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

// sanitizeLaunchUsername 清洗进入游戏命令行参数的用户名。
// 老版本 version JSON 的 MinecraftArgs 是按空格切分的字符串，
// 用户名里只要含空格/制表符/控制字符，就能在 ${auth_player_name} 处
// 注入任意额外游戏参数（参数注入）。这里剔除空白与控制字符、按 16 个
// rune 截断（Minecraft 用户名上限），清洗后为空则回退 Player。
// 正版用户名本身只会含字母数字下划线，此清洗不影响正常用户。
func sanitizeLaunchUsername(raw string) string {
	var b strings.Builder
	count := 0
	for _, r := range raw {
		if count >= 16 {
			break
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
		count++
	}
	name := b.String()
	if name == "" {
		return "Player"
	}
	return name
}

func (a *App) buildLaunchArgs(versionID string, versionJSON *VersionJSON, mcDir string, versionDir string) ([]string, string, string, string) {
	isOldJSON := versionJSON.MinecraftArgs != ""
	javaEntry, _ := a.SelectJavaForVersion(versionID)
	maxMem, minMem := "2G", "1G"
	if config, _ := a.GetGlobalConfig(); config != nil {
		// r34：-Xmx/-Xms 不再裸拼 config 整数。SaveGlobalConfig 不校验堆配置，旧实现
		// 会把 0 / 负数 / 极大值 / min>max 原样拼成 "-Xmx1000000G" 等非法参数导致 JVM
		// 启动失败。统一在拼接点走 heapsizeguard 归一（GB 口径、1TiB 上界、min<=max），
		// 任何收敛都记录一次安全审计，便于排查被改脏的配置。
		safeMin, safeMax, heapCodes := ResolveHeapSizesGB(config.MinMemory, config.MaxMemory)
		if len(heapCodes) > 0 {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityWarn, auditActionStripped,
				"minecraft", "游戏堆内存配置已归一: "+strings.Join(heapCodes, ","))
		}
		maxMem = FormatHeapSizeGB(safeMax)
		minMem = FormatHeapSizeGB(safeMin)
	}
	nativesDir := filepath.Join(versionDir, versionID+"-natives")
	classpathEntries := a.buildClasspath(mcDir, versionID, versionJSON)

	// 最终归属验收（必须在 resolveJVMArg 使用 classpath 拼出 -cp 之前完成）：不相信
	// buildClasspath 内各拼路径环节，对整条 classpath 统一收敛——必须全部是 .minecraft
	// 内的绝对 .jar、无 UNC/穿越/控制符，并去重。越界条目剔除并留痕，用安全去重后的
	// 条目重建 classpath；后续 Forge 过滤只会再收窄（仍是安全子集）。
	cpAudit := AuditGameClasspath(classpathEntries, []string{mcDir})
	for _, f := range cpAudit.Findings {
		if f.Severity == launchSeverityCritical {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
				"minecraft", "游戏 classpath 不安全条目已剔除: "+f.Code)
		}
	}
	if len(cpAudit.SafeEntries) != len(classpathEntries) {
		classpathEntries = cpAudit.SafeEntries
	}
	classpath := strings.Join(classpathEntries, ";")
	if lpAudit := AuditGameLocalPaths(nativesDir, filepath.Join(mcDir, "libraries"),
		filepath.Join(mcDir, "assets"), []string{mcDir}); lpAudit.HasCritical() {
		recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionBlocked,
			"minecraft", "游戏本地路径(natives/libraries/assets)审计未通过: "+lpAudit.FirstCriticalCode())
	}
	gameDir := versionDir
	if !a.IsVersionIsolation() {
		gameDir = mcDir
	}

	var jvmArgs []string
	if isOldJSON {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			"-XX:+UnlockExperimentalVMOptions", "-XX:+UseG1GC",
			"-XX:G1NewSizePercent=20", "-XX:G1ReservePercent=20",
			"-XX:MaxGCPauseMillis=50", "-XX:G1HeapRegionSize=32M",
		}
	} else {
		jvmArgs = []string{
			fmt.Sprintf("-Xmx%s", maxMem), fmt.Sprintf("-Xms%s", minMem),
			fmt.Sprintf("-Djava.library.path=%s", nativesDir),
			fmt.Sprintf("-Dorg.lwjgl.librarypath=%s", nativesDir),
		}
		if versionJSON.Arguments != nil {
			var untrusted []string
			for _, arg := range versionJSON.Arguments.JVM {
				untrusted = append(untrusted, resolveJVMArg(arg, nativesDir, mcDir, classpath, versionID)...)
			}
			// arguments.jvm 来自 Mojang/加载器下发的版本 JSON，本质上是外部数据。
			// 被篡改或恶意的整合包版本 JSON 可在此塞入 -javaagent / -XX:OnError
			// 等参数，在 JVM 启动阶段直接执行任意代码（见 filterUntrustedJvmArgs）。
			safeJvmArgs, blockedJvmArgs, jvmArgTruncated := filterUntrustedJvmArgs(untrusted)
			jvmArgs = append(jvmArgs, safeJvmArgs...)
			for _, bad := range blockedJvmArgs {
				a.writeLog("已拦截版本 JSON 中的危险 JVM 参数: %s", bad)
			}
			if jvmArgTruncated {
				a.writeLog("版本 JSON 的 JVM 参数数量超过 %d，多余参数已丢弃", maxUntrustedJvmArgs)
			}
		}
	}

	isForgeNew := (strings.Contains(versionID, "forge") || strings.Contains(versionJSON.MainClass, "bootstraplauncher")) && javaEntry.MajorVer >= 17
	if isForgeNew {
		var filtered []string
		for _, entry := range classpathEntries {
			if strings.Contains(entry, "versions") && strings.HasSuffix(entry, ".jar") {
				base := strings.ToLower(strings.TrimSuffix(filepath.Base(entry), ".jar"))
				if !strings.Contains(base, "forge") && !strings.Contains(base, "fabric") &&
					!strings.Contains(base, "neoforge") && !strings.Contains(base, "quilt") {
					continue
				}
			}
			filtered = append(filtered, entry)
		}
		classpathEntries = filtered
		classpath = strings.Join(classpathEntries, ";")
	}

	isFabric := strings.Contains(versionID, "fabric") || strings.Contains(versionJSON.MainClass, "fabricmc") || strings.Contains(versionJSON.MainClass, "knot")
	if isFabric && len(classpathEntries) > 0 {
		var paths []string
		for _, p := range classpathEntries {
			paths = append(paths, "file:///"+strings.ReplaceAll(p, "\\", "/"))
		}
		jvmArgs = append(jvmArgs, "-Dfabric.classPathGroups=default:"+strings.Join(paths, ";"))
	}
	jvmArgs = deduplicateJvmArgs(jvmArgs)
	// 安全缓解属性必须由启动器拍板：剔除来自启动器/版本 JSON/加载器的任何同名 -D
	// （防止不可信 JSON 用后置 =false 覆盖 formatMsgNoLookups），并在 JVM 参数段
	// 末尾统一下发 log4j 消息 lookup 关闭与 JNDI 远程 codebase 禁用。
	jvmArgs = applyEnforcedJvmProperties(jvmArgs)

	username := "Player"
	currentUser, err := a.GetCurrentUser()
	if err == nil && currentUser.Username != "" {
		username = sanitizeLaunchUsername(currentUser.Username)
	}
	uuid := generateOfflineUUID(username)
	accessToken := uuid
	userType := "msa"

	if currentUser.Type == UserTypePremium {
		authData, authErr := a.GetMSAuthData(username)
		if authErr == nil && authData.MCAccessToken != "" {
			_ = a.RefreshMicrosoftToken(username)
			authData, authErr = a.GetMSAuthData(username)
			if authErr == nil {
				uuid = authData.UUID
				accessToken = authData.MCAccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}
	if currentUser.Type == UserTypeExternal {
		extData, extErr := a.GetExternalAuthData(username)
		if extErr == nil && extData.AccessToken != "" {
			_ = a.RefreshExternalToken(username)
			extData, extErr = a.GetExternalAuthData(username)
			if extErr == nil {
				uuid = extData.UUID
				accessToken = extData.AccessToken
				if len(uuid) == 32 {
					uuid = fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:32])
				}
			}
		}
	}

	assetIndexName := ""
	if versionJSON.AssetIndex != nil {
		assetIndexName = versionJSON.AssetIndex.ID
	}
	replacements := map[string]string{
		"${auth_player_name}": username, "${version_name}": versionID,
		"${game_directory}": gameDir, "${assets_root}": filepath.Join(mcDir, "assets"),
		"${assets_index_name}": assetIndexName, "${auth_uuid}": uuid,
		"${auth_access_token}": accessToken, "${access_token}": accessToken,
		"${auth_session}": accessToken, "${user_type}": userType,
		"${version_type}": "QGL", "${user_properties}": "{}",
		"${game_assets}": filepath.Join(mcDir, "assets", "virtual", "legacy"),
		"${classpath}":   classpath, "${classpath_separator}": ";",
		"${natives_directory}": nativesDir, "${library_directory}": filepath.Join(mcDir, "libraries"),
		"${launcher_name}": "QGL", "${launcher_version}": "1.0.0",
		"${resolution_width}": "854", "${resolution_height}": "480",
	}

	// 启动器自己生成、随后替换进游戏参数的可信值（账号用户名/UUID/会话令牌/资源索引
	// ID）必须干净：它们一旦含空白、引号或 CR/LF，就会在被字符串替换拼进 argv 时劈开
	// 额外参数（旧版 MinecraftArgs 是纯字符串替换，尤其敏感）。账号数据可能来自损坏的
	// 本地账号文件或异常的第三方认证响应，这里统一做控制字符/超长兜底，命中即放弃启动。
	reservedValues := map[string]string{
		"username":    username,
		"uuid":        uuid,
		"accessToken": accessToken,
		"assetIndex":  assetIndexName,
		"version":     versionID,
		"userType":    userType,
	}
	rvAudit := AuditReservedGameValues(reservedValues)
	if rvAudit.HasCritical() {
		for _, f := range rvAudit.Findings {
			if f.Severity == launchSeverityCritical {
				recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionRejected,
					"minecraft", "启动器保留参数值异常: "+f.Code+" @ "+f.Field)
			}
		}
		a.writeLog("账号/会话参数含非法控制字符或超长，放弃启动")
		return nil, "", "", ""
	}

	var gameArgs []string
	if isOldJSON {
		for _, part := range strings.Split(versionJSON.MinecraftArgs, " ") {
			arg := part
			for k, v := range replacements {
				arg = strings.ReplaceAll(arg, k, v)
			}
			gameArgs = append(gameArgs, arg)
		}
	}
	if versionJSON.Arguments != nil {
		for _, arg := range versionJSON.Arguments.Game {
			gameArgs = append(gameArgs, resolveGameArg(arg, replacements)...)
		}
	}

	// 游戏参数最终验收：旧版 MinecraftArgs 与 arguments.game 都来自外部版本 JSON。
	// resolveGameArg 已挡住“一个值夹空格劈成多条”，这里再拦“本身合法成条”的会话劫持
	// 参数（--server/--port/--quickPlay*/--proxy*，官方 JSON 绝不会自带）与控制字符/
	// 超长值，并给条数上界。剔除劫持项后可继续；参数表被畸形放大则放弃启动。
	gaAudit := AuditExternalGameArgs(gameArgs)
	for _, f := range gaAudit.Findings {
		if f.Severity == launchSeverityCritical {
			recordSecurityEvent(auditCategoryLaunch, auditSeverityCritical, auditActionStripped,
				"minecraft", "外部游戏参数审计: "+f.Code+" @ "+f.Field)
		}
	}
	if gameFindingsContainCode(gaAudit.Findings, "ga-too-many") {
		a.writeLog("外部游戏参数条数超过上限，放弃启动")
		return nil, "", "", ""
	}
	gameArgs = gaAudit.SafeExternal

	hasCp := false
	for i, arg := range jvmArgs {
		if arg == "-cp" && i+1 < len(jvmArgs) {
			hasCp = true
		}
	}
	var allArgs []string
	if hasCp {
		allArgs = append(jvmArgs, versionJSON.MainClass)
	} else {
		allArgs = append(jvmArgs, "-cp", classpath, versionJSON.MainClass)
	}
	allArgs = append(allArgs, gameArgs...)
	return allArgs, classpath, username, gameDir
}
