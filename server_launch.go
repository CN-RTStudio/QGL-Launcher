package main

import (
	"bufio"
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

func (a *App) StartServer(name string) error {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	if serverMgr.status.Running {
		return fmt.Errorf("服务器已在运行中")
	}

	cfg, err := a.getServerConfig(name)
	if err != nil {
		return err
	}
	if isPathTraversal(a.GetServerDir(), cfg.ServerDir) {
		return fmt.Errorf("服务器目录路径不安全，拒绝启动")
	}

	// 启动目标审计：cfg.Version 由用户配置可控，直接拼 "<v>-server.jar" 时若版本名
	// 含分隔符 / ".." / 绝对前缀，-jar 会相对 cmd.Dir 解析到 ServerDir 之外的 jar
	// （=加载攻击者放置的类）。这里把工作目录、拼出的 jar 与内存边界统一收敛到
	// launchtarget 内核，critical 一律拒绝启动。
	serverRoot := a.GetServerDir()
	launchAudit := AuditServerLaunch(cfg.ServerDir, cfg.Version, cfg.MinMemory, cfg.MaxMemory, []string{serverRoot})
	if launchAudit.HasCritical() {
		return fmt.Errorf("服务器启动目标校验失败，拒绝启动: %s", launchAudit.FirstCriticalCode())
	}

	if err := a.auditWorldForLaunch(cfg.ServerDir); err != nil {
		return err
	}

	settingsAudit, settingsErr := AuditServerSettingsFile(cfg.ServerDir)
	if settingsErr != nil {
		return settingsErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器配置", "服务器配置", cfg.ServerDir, settingsAudit); err != nil {
		return err
	}

	bindingAudit, bindingErr := AuditServerBinding(cfg.ServerDir)
	if bindingErr != nil {
		return bindingErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器网络暴露策略", "服务器网络暴露", bindingAudit.Path, bindingAudit); err != nil {
		return err
	}

	packAudit, packErr := AuditServerResourcePack(cfg.ServerDir)
	if packErr != nil {
		return packErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器资源包策略", "服务器资源包", packAudit.Path, packAudit); err != nil {
		return err
	}

	logAudit, logErr := AuditServerLogs(cfg.ServerDir)
	if logErr != nil {
		return logErr
	}
	if err := a.gateLaunchAudit(auditCategoryLaunch, "服务器日志目录", "服务器日志", logAudit.Dir, logAudit); err != nil {
		return err
	}

	rconAudit, rconErr := AuditServerRcon(cfg.ServerDir)
	if rconErr != nil {
		return rconErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器 RCON/Query 暴露面", "服务器 RCON/Query ", rconAudit.Path, rconAudit); err != nil {
		return err
	}

	startupAudit := AuditServerStartupScripts(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryLaunch, "服务器启动脚本", "服务器启动脚本", cfg.ServerDir, startupAudit); err != nil {
		return err
	}

	proxyAudit := AuditServerProxyTrust(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器代理信任配置", "服务器代理信任", cfg.ServerDir, proxyAudit); err != nil {
		return err
	}

	fsPermAudit := AuditServerFSPermissions(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器目录权限", "服务器目录权限", cfg.ServerDir, fsPermAudit); err != nil {
		return err
	}

	strayAudit := AuditServerStraySecrets(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器目录凭据", "服务器目录凭据", cfg.ServerDir, strayAudit); err != nil {
		return err
	}

	whitelistAudit := AuditServerWhitelist(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器白名单", "服务器白名单", cfg.ServerDir, whitelistAudit); err != nil {
		return err
	}

	banAudit := AuditServerBanList(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器封禁名单", "服务器封禁名单", cfg.ServerDir, banAudit); err != nil {
		return err
	}

	iconAudit := AuditServerIcon(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器图标", "服务器图标", cfg.ServerDir, iconAudit); err != nil {
		return err
	}

	dataPackAudit := AuditServerDataPacks(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryZip, "服务器数据包", "服务器数据包", cfg.ServerDir, dataPackAudit); err != nil {
		return err
	}

	accessControlAudit := AuditServerAccessControl(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器访问控制", "服务器访问控制", cfg.ServerDir, accessControlAudit); err != nil {
		return err
	}

	pluginJarAudit := AuditServerPluginJars(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryJarScan, "服务器插件 jar ", "服务器插件 jar ", cfg.ServerDir, pluginJarAudit); err != nil {
		return err
	}

	crashReportAudit := AuditCrashReports(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器崩溃报告", "服务器崩溃报告", cfg.ServerDir, crashReportAudit); err != nil {
		return err
	}

	tlsAudit := AuditServerTLS(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器 TLS ", "服务器 TLS ", cfg.ServerDir, tlsAudit); err != nil {
		return err
	}

	worldRegionAudit := AuditServerWorldRegions(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器世界存档", "服务器世界存档", cfg.ServerDir, worldRegionAudit); err != nil {
		return err
	}

	portBindingAudit := AuditServerPorts(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器端口绑定", "服务器端口绑定", cfg.ServerDir, portBindingAudit); err != nil {
		return err
	}

	logConfigAudit := AuditServerLogConfig(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器日志配置", "服务器日志配置", cfg.ServerDir, logConfigAudit); err != nil {
		return err
	}

	tickConfigAudit := AuditServerTickConfig(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器 tick 参数", "服务器 tick 参数", cfg.ServerDir, tickConfigAudit); err != nil {
		return err
	}

	jvmAgentAudit := AuditServerJVMAgents(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryJVMEnv, "服务器 JVM agent ", "服务器 JVM agent ", cfg.ServerDir, jvmAgentAudit); err != nil {
		return err
	}

	budgetAudit := AuditServerBudget(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器磁盘占用", "服务器磁盘占用", cfg.ServerDir, budgetAudit); err != nil {
		return err
	}

	playerPrivacyAudit := AuditServerPlayerPrivacy(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("玩家身份数据审计阻断启动: ", "玩家身份数据未通过安全校验", playerPrivacyAudit); err != nil {
		return err
	}
	forkConfigAudit := AuditServerForkConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("分支配置审计阻断启动: ", "分支配置未通过安全校验", forkConfigAudit); err != nil {
		return err
	}
	yamlHazardAudit := AuditServerYamlHazards(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("YAML 构造审计阻断启动: ", "YAML 配置未通过安全校验", yamlHazardAudit); err != nil {
		return err
	}
	permissionConfigAudit := AuditServerPermissionConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("权限配置审计阻断启动: ", "权限配置未通过安全校验", permissionConfigAudit); err != nil {
		return err
	}
	startupSecretAudit := AuditServerStartupSecrets(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("启动脚本凭据审计阻断启动: ", "启动脚本凭据未通过安全校验", startupSecretAudit); err != nil {
		return err
	}
	commandAliasAudit := AuditServerCommandAliases(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("命令别名审计阻断启动: ", "命令别名未通过安全校验", commandAliasAudit); err != nil {
		return err
	}
	helpOverrideAudit := AuditServerHelpOverride(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("帮助覆盖审计阻断启动: ", "帮助覆盖未通过安全校验", helpOverrideAudit); err != nil {
		return err
	}
	statsAudit := AuditServerStats(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("玩家统计审计阻断启动: ", "玩家统计未通过安全校验", statsAudit); err != nil {
		return err
	}
	advancementAudit := AuditServerAdvancements(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("进度数据审计阻断启动: ", "进度数据未通过安全校验", advancementAudit); err != nil {
		return err
	}
	dataPackFilterAudit := AuditServerDataPackFilters(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("数据包过滤审计阻断启动: ", "数据包过滤未通过安全校验", dataPackFilterAudit); err != nil {
		return err
	}
	log4jAudit := AuditServerLog4jShell(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("log4j 组件审计阻断启动: ", "log4j 组件未通过安全校验", log4jAudit); err != nil {
		return err
	}
	proxyForwardAudit := AuditServerProxyForwarding(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("代理转发审计阻断启动: ", "代理转发配置未通过安全校验", proxyForwardAudit); err != nil {
		return err
	}
	connectionFloodAudit := AuditServerConnectionFlood(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("连接洪泛审计阻断启动: ", "连接节流配置未通过安全校验", connectionFloodAudit); err != nil {
		return err
	}
	packetLimiterAudit := AuditServerPacketLimiter(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("数据包限速审计阻断启动: ", "数据包限速配置未通过安全校验", packetLimiterAudit); err != nil {
		return err
	}
	propertiesBudgetAudit := AuditServerPropertiesBudget(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("服务端属性预算审计阻断启动: ", "服务端属性未通过安全校验", propertiesBudgetAudit); err != nil {
		return err
	}
	modJarAudit := AuditModJarManifests(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("模组清单审计阻断启动: ", "模组清单未通过安全校验", modJarAudit); err != nil {
		return err
	}
	pluginJarEntryAudit := AuditPluginJarEntries(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("插件归档审计阻断启动: ", "插件归档未通过安全校验", pluginJarEntryAudit); err != nil {
		return err
	}
	commandBlockAudit := AuditServerCommandBlocks(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("命令方块审计阻断启动: ", "命令方块配置未通过安全校验", commandBlockAudit); err != nil {
		return err
	}
	pluginUpdateAudit := AuditServerPluginUpdates(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("插件更新审计阻断启动: ", "插件更新配置未通过安全校验", pluginUpdateAudit); err != nil {
		return err
	}
	pluginMetricsAudit := AuditServerPluginMetrics(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("插件遥测审计阻断启动: ", "插件遥测配置未通过安全校验", pluginMetricsAudit); err != nil {
		return err
	}
	queryBindingAudit := AuditServerQueryBinding(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("查询绑定审计阻断启动: ", "查询绑定配置未通过安全校验", queryBindingAudit); err != nil {
		return err
	}
	entityCrammingAudit := AuditServerEntityCramming(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("实体堆积审计阻断启动: ", "实体堆积配置未通过安全校验", entityCrammingAudit); err != nil {
		return err
	}
	movementGuardAudit := AuditServerMovementGuards(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("移动容量审计阻断启动: ", "移动容量配置未通过安全校验", movementGuardAudit); err != nil {
		return err
	}
	proxyAuthAudit := AuditServerProxyAuth(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("代理鉴权审计阻断启动: ", "服务器代理鉴权配置未通过安全校验", proxyAuthAudit); err != nil {
		return err
	}
	antiXrayAudit := AuditServerAntiXray(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("反矿透审计阻断启动: ", "服务器反矿透配置未通过安全校验", antiXrayAudit); err != nil {
		return err
	}
	watchdogAudit := AuditServerWatchdog(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("看门狗审计阻断启动: ", "服务器看门狗与重启配置未通过安全校验", watchdogAudit); err != nil {
		return err
	}
	pregenAudit := AuditServerPregen(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("区块预生成审计阻断启动: ", "服务器区块预生成配置未通过安全校验", pregenAudit); err != nil {
		return err
	}
	dynmapAudit := AuditServerDynmap(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("网页地图审计阻断启动: ", "服务器网页地图配置未通过安全校验", dynmapAudit); err != nil {
		return err
	}
	unsafeToggleAudit := AuditServerUnsafeToggles(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("实验开关审计阻断启动: ", "服务器实验性开关未通过安全校验", unsafeToggleAudit); err != nil {
		return err
	}
	blueMapAudit := AuditServerBlueMap(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("网页地图审计阻断启动: ", "网页地图审计未通过安全校验", blueMapAudit); err != nil {
		return err
	}
	userCacheAudit := AuditServerUserCache(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("玩家缓存审计阻断启动: ", "玩家缓存审计未通过安全校验", userCacheAudit); err != nil {
		return err
	}
	bannedIPsAudit := AuditServerBannedIPs(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("IP 封禁清单审计阻断启动: ", "IP 封禁清单审计未通过安全校验", bannedIPsAudit); err != nil {
		return err
	}
	bukkitConfigAudit := AuditServerBukkitConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("Bukkit 配置审计阻断启动: ", "Bukkit 配置审计未通过安全校验", bukkitConfigAudit); err != nil {
		return err
	}
	worldNameAudit := AuditServerWorldName(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("世界目录审计阻断启动: ", "世界目录审计未通过安全校验", worldNameAudit); err != nil {
		return err
	}
	worldSeedAudit := AuditServerWorldSeed(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("世界种子审计阻断启动: ", "世界种子审计未通过安全校验", worldSeedAudit); err != nil {
		return err
	}
	opsJsonAudit := AuditServerOpsJson(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("操作员清单审计阻断启动: ", "服务器操作员清单未通过安全校验", opsJsonAudit); err != nil {
		return err
	}
	whitelistFileAudit := AuditServerWhitelistFile(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("白名单文件审计阻断启动: ", "服务器白名单文件未通过安全校验", whitelistFileAudit); err != nil {
		return err
	}
	commandsYmlAudit := AuditServerCommandsYml(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("命令别名审计阻断启动: ", "服务器命令别名配置未通过安全校验", commandsYmlAudit); err != nil {
		return err
	}
	helpYmlAudit := AuditServerHelpYml(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("帮助配置审计阻断启动: ", "服务器帮助配置未通过安全校验", helpYmlAudit); err != nil {
		return err
	}
	spigotAudit := AuditServerSpigotConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("Spigot 配置审计阻断启动: ", "服务器 Spigot 配置未通过安全校验", spigotAudit); err != nil {
		return err
	}
	paperAudit := AuditServerPaperConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("Paper 全局配置审计阻断启动: ", "服务器 Paper 全局配置未通过安全校验", paperAudit); err != nil {
		return err
	}
	eulaAudit := AuditServerEula(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("EULA 协议审计阻断启动: ", "服务器 EULA 协议未通过安全校验", eulaAudit); err != nil {
		return err
	}
	iconFileAudit := AuditServerIconFile(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("服务器图标审计阻断启动: ", "服务器图标未通过安全校验", iconFileAudit); err != nil {
		return err
	}
	permissionsFileAudit := AuditServerPermissions(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("权限配置审计阻断启动: ", "服务器权限配置未通过安全校验", permissionsFileAudit); err != nil {
		return err
	}
	bannedPlayersFileAudit := AuditServerBannedPlayers(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("封禁名单审计阻断启动: ", "服务器封禁名单未通过安全校验", bannedPlayersFileAudit); err != nil {
		return err
	}
	paperWorldAudit := AuditServerPaperWorldDefaults(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("Paper 世界默认配置审计阻断启动: ", "服务器 Paper 世界默认配置未通过安全校验", paperWorldAudit); err != nil {
		return err
	}
	purpurConfigAudit := AuditServerPurpurConfig(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("Purpur 配置审计阻断启动: ", "服务器 Purpur 配置未通过安全校验", purpurConfigAudit); err != nil {
		return err
	}
	levelDataAudit := AuditServerLevelData(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("存档元数据审计阻断启动: ", "服务器存档元数据未通过安全校验", levelDataAudit); err != nil {
		return err
	}
	propertiesEncodingAudit := AuditServerPropertiesEncoding(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("属性文件编码审计阻断启动: ", "服务器属性文件编码未通过安全校验", propertiesEncodingAudit); err != nil {
		return err
	}
	jvmArgsFileAudit := AuditServerJvmArgsFile(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("JVM 参数审计阻断启动: ", "服务器 JVM 参数未通过安全校验", jvmArgsFileAudit); err != nil {
		return err
	}
	crashReportsAudit := AuditServerCrashReports(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("崩溃报告审计阻断启动: ", "服务器崩溃报告未通过安全校验", crashReportsAudit); err != nil {
		return err
	}
	configConsistencyAudit := AuditServerConfigConsistency(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("配置一致性审计阻断启动: ", "服务器配置组合未通过安全校验", configConsistencyAudit); err != nil {
		return err
	}
	onlineModeAudit := AuditServerOnlineMode(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("在线认证审计阻断启动: ", "server.properties 在线认证配置未通过安全校验", onlineModeAudit); err != nil {
		return err
	}
	motdControlAudit := AuditServerMotdControl(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("MOTD 控制字符审计阻断启动: ", "MOTD 文本未通过安全校验", motdControlAudit); err != nil {
		return err
	}
	propsStructureAudit := AuditServerPropertiesStructure(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("属性文件结构审计阻断启动: ", "server.properties 结构未通过安全校验", propsStructureAudit); err != nil {
		return err
	}
	whitelistCoverageAudit := AuditServerWhitelistCoverage(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("白名单覆盖审计阻断启动: ", "白名单覆盖配置未通过安全校验", whitelistCoverageAudit); err != nil {
		return err
	}
	hardcoreAudit := AuditServerHardcore(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("难度模式审计阻断启动: ", "难度与游戏模式配置未通过安全校验", hardcoreAudit); err != nil {
		return err
	}
	maxPlayersAudit := AuditServerMaxPlayers(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("容量限流审计阻断启动: ", "容量与限流配置未通过安全校验", maxPlayersAudit); err != nil {
		return err
	}
	banEnforcementAudit := AuditServerBanEnforcement(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("封禁名单审计阻断启动: ", "封禁与管理员名单未通过安全校验", banEnforcementAudit); err != nil {
		return err
	}
	exploitTogglesAudit := AuditServerExploitToggles(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("作弊开关审计阻断启动: ", "作弊与权限开关配置未通过安全校验", exploitTogglesAudit); err != nil {
		return err
	}
	worldSymlinkAudit := AuditServerWorldSymlinks(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("世界存档符号链接审计阻断启动: ", "世界存档目录未通过安全校验", worldSymlinkAudit); err != nil {
		return err
	}
	opsPrivilegeAudit := AuditServerOpsPrivilege(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("运维权限审计阻断启动: ", "运维权限配置未通过安全校验", opsPrivilegeAudit); err != nil {
		return err
	}
	rconHardeningAudit := AuditServerRconHardening(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("RCON 加固审计阻断启动: ", "RCON 配置未通过安全校验", rconHardeningAudit); err != nil {
		return err
	}
	queryExposureAudit := AuditServerQueryExposure(cfg.ServerDir)
	if err := a.gateLaunchSecurityStop("对外暴露审计阻断启动: ", "对外暴露配置未通过安全校验", queryExposureAudit); err != nil {
		return err
	}
	pluginConfigAudit := AuditServerPluginConfig(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器插件配置", "服务器插件配置", cfg.ServerDir, pluginConfigAudit); err != nil {
		return err
	}

	backupAudit := AuditServerBackups(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPrivateWrite, "服务器备份", "服务器备份", cfg.ServerDir, backupAudit); err != nil {
		return err
	}

	libraryAudit := AuditServerLibraries(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryJarScan, "服务器依赖库", "服务器依赖库", cfg.ServerDir, libraryAudit); err != nil {
		return err
	}

	sessionLockAudit := AuditServerSessionLocks(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryReclaim, "服务器世界占用", "服务器世界占用", cfg.ServerDir, sessionLockAudit); err != nil {
		return err
	}

	jmxAudit := AuditServerJMX(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器 JMX 暴露面", "服务器 JMX 暴露面", cfg.ServerDir, jmxAudit); err != nil {
		return err
	}

	jarCpAudit := AuditServerJarClassPath(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryJarScan, "服务器 jar Class-Path ", "服务器 jar Class-Path ", cfg.ServerDir, jarCpAudit); err != nil {
		return err
	}

	envAudit := AuditServerEnvironmentHijack(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryJVMEnv, "服务器环境变量", "服务器环境变量", cfg.ServerDir, envAudit); err != nil {
		return err
	}

	pluginPermAudit := AuditServerPluginPermissions(cfg.ServerDir)
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器插件权限", "服务器插件权限", cfg.ServerDir, pluginPermAudit); err != nil {
		return err
	}

	accessAudit, accessErr := AuditServerAccess(cfg.ServerDir)
	if accessErr != nil {
		return accessErr
	}
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器权限文件", "服务器权限", cfg.ServerDir, accessAudit); err != nil {
		return err
	}

	operatorAudit, operatorErr := AuditServerOperators(cfg.ServerDir)
	if operatorErr != nil {
		return operatorErr
	}
	if err := a.gateLaunchAudit(auditCategoryPermission, "服务器权限名单", "服务器权限名单", cfg.ServerDir, operatorAudit); err != nil {
		return err
	}

	playerCacheAudit, playerCacheErr := AuditPlayerCache(cfg.ServerDir)
	if playerCacheErr != nil {
		return playerCacheErr
	}
	if err := a.gateLaunchAudit(auditCategoryPermission, "玩家缓存", "玩家缓存", playerCacheAudit.Path, playerCacheAudit); err != nil {
		return err
	}

	pluginAudit, pluginErr := AuditServerPlugins(cfg.ServerDir)
	if pluginErr != nil {
		return pluginErr
	}
	if err := a.gateLaunchAudit(auditCategoryPermission, "插件目录", "插件", pluginAudit.Dir, pluginAudit); err != nil {
		return err
	}

	modManifestAudit, modManifestErr := AuditServerModManifest(filepath.Join(cfg.ServerDir, "mods"))
	if modManifestErr != nil {
		return modManifestErr
	}
	if err := a.gateLaunchAudit(auditCategoryJarScan, "模组清单", "模组清单", modManifestAudit.Dir,
		gateView{modManifestAudit.Blocking(), modManifestAudit.HasWarnings(), modManifestAudit.Describe()}); err != nil {
		return err
	}

	remoteAudit, remoteErr := AuditServerRemoteAdmin(cfg.ServerDir)
	if remoteErr != nil {
		return remoteErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "服务器远程管理配置", "服务器远程管理", remoteAudit.Path, remoteAudit); err != nil {
		return err
	}

	portAudit, portErr := AuditServerPortExposure(cfg.ServerDir)
	if portErr != nil {
		return portErr
	}
	if err := a.gateLaunchAudit(auditCategoryConfig, "端口暴露", "端口暴露", portAudit.Path, portAudit); err != nil {
		return err
	}

	surfaceAudit, surfaceErr := AuditServerSurface(cfg.ServerDir)
	if surfaceErr != nil {
		return surfaceErr
	}
	if err := a.gateLaunchAudit(auditCategoryLaunch, "服务器目录根层", "服务器目录根层", cfg.ServerDir, surfaceAudit); err != nil {
		return err
	}

	baselineAudit, baselineErr := AuditServerConfigBaseline(cfg.ServerDir, "")
	if baselineErr != nil {
		a.writeLog("服务器配置基线不可用: %v", baselineErr)
	} else if baselineAudit.HasWarnings() {
		a.writeLog("服务器配置基线变化: %s", baselineAudit.Describe())
	}

	javaEntry, err := a.SelectJavaForVersion(cfg.Version)
	if err != nil {
		return fmt.Errorf("选择 Java 失败: %v", err)
	}
	javaPath := javaEntry.Path
	// AuditServerLaunch 只收敛了工作目录/版本名拼出的 jar/内存，java 可执行路径由
	// SelectJavaForVersion 决定，这里在真正 exec 前再做一次绝对/UNC/穿越/扩展名校验，
	// 防止被改写的 JDK 记录或解析结果把服务器 JVM 指到网络共享或穿越路径。
	if javaFindings := auditJavaExe(javaPath); len(javaFindings) > 0 {
		return fmt.Errorf("服务器 java 可执行审计未通过，拒绝启动: %s", javaFindings[0].Code)
	}

	jarName := cfg.Version + "-server.jar"
	jarPath := filepath.Join(cfg.ServerDir, jarName)
	jarAudit, jarAuditErr := AuditServerJar(jarPath, func(path string) (bool, bool) {
		meta, ok := loadCachedFileMeta(path)
		if !ok {
			return false, false
		}
		return a.verifyCachedFile(path, meta.SHA1), true
	})
	if jarAuditErr != nil {
		return fmt.Errorf("服务端 JAR 完整性检查失败: %v", jarAuditErr)
	}
	if err := a.gateLaunchAudit(auditCategoryLaunch, "服务端 JAR 完整性", "服务端 JAR 校验", jarPath,
		gateView{jarAudit.Blocking(), len(jarAudit.Warnings) > 0, describeServerJarAudit(jarAudit)}); err != nil {
		return err
	}
	maxMem := fmt.Sprintf("%dM", cfg.MaxMemory)
	minMem := fmt.Sprintf("%dM", cfg.MinMemory)
	// 专用服务端会把玩家名 / 聊天经 log4j 记入控制台，旧版服务端 jar 同样受 Log4Shell
	// 影响（攻击者进服即可投递 JNDI 载荷）。这些 JVM 参数全由启动器生成，没有外部
	// JSON 覆盖问题，但仍统一走强制内核：补 log4j 消息 lookup 关闭与 JNDI 远程
	// codebase 禁用，再拼 -jar / nogui 程序参数。
	jvmArgs := applyEnforcedJvmProperties([]string{
		"-server",
		"-XX:+UseG1GC",
		fmt.Sprintf("-Xmx%s", maxMem),
		fmt.Sprintf("-Xms%s", minMem),
		"-XX:+UseCompressedOops",
	})
	args := append(jvmArgs, "-jar", jarName, "nogui")

	cmd := exec.Command(javaPath, args...)
	cmd.Dir = cfg.ServerDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// 内置服务端是长期运行的独立 JVM，同样必须剥离 JAVA_TOOL_OPTIONS
	// 一族隐式参数变量，避免服务端进程被环境注入 javaagent / 恶意类路径。
	a.applySanitizedJVMEnv(cmd, "DedicatedServer", nil)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("获取 stdin 失败: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取 stdout 失败: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取 stderr 失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动服务器失败: %v", err)
	}

	readyCh := make(chan struct{}, 1)
	serverMgr.cmd = cmd
	serverMgr.stdin = stdin
	serverMgr.logBuffer = make([]string, 0)
	serverMgr.ctx = a.ctx
	serverMgr.readyCh = readyCh
	serverMgr.status = ServerStatus{
		Running: true,
		Name:    name,
		Version: cfg.Version,
		Port:    cfg.Port,
		PID:     cmd.Process.Pid,
		Ready:   false,
	}
	// 新一轮服务端进程：清空上一会话遗留的控制台灌入冷却 / 窗口计数。
	serverConsoleGate.reset()

	go func() {
		scanner := make(chan string, 200)
		var wg sync.WaitGroup
		pipeOutput := func(r io.Reader) {
			defer wg.Done()
			s := bufio.NewScanner(r)
			// 服务端日志通常很短，但堆栈 / JSON 单行可能到几十 KB；
			// 缓冲区上限 1 MiB，超出的异常超长行直接结束扫描，避免无界增长。
			s.Buffer(make([]byte, 0, 64*1024), maxServerLogLineBytes)
			for s.Scan() {
				line := stripControlSequences(strings.TrimRight(s.Text(), "\r"))
				if line != "" {
					scanner <- line
				}
			}
		}
		wg.Add(2)
		go pipeOutput(stdout)
		go pipeOutput(stderr)
		// 两个读取协程都退出（进程结束、管道关闭）后再关闭 channel，
		// 否则外层 range 永久阻塞，每次启动服务器都会泄漏一个协程。
		go func() {
			wg.Wait()
			close(scanner)
		}()
		for line := range scanner {
			serverMgr.mu.Lock()
			serverMgr.logBuffer = append(serverMgr.logBuffer, line)
			if len(serverMgr.logBuffer) > 500 {
				serverMgr.logBuffer = serverMgr.logBuffer[len(serverMgr.logBuffer)-500:]
			}
			if !serverMgr.status.Ready {
				if (strings.Contains(line, "Done (") && strings.Contains(line, ")! For help, type \"help\"")) ||
					(strings.Contains(line, "完成 (") && strings.Contains(line, ")! 如需帮助，请输入 \"help\"")) {
					serverMgr.status.Ready = true
					select {
					case readyCh <- struct{}{}:
					default:
					}
					runtime.EventsEmit(serverMgr.ctx, "serverReady")
					runtime.EventsEmit(serverMgr.ctx, "serverStatus", serverMgr.status)
				}
			}
			serverMgr.mu.Unlock()
			runtime.EventsEmit(a.ctx, "serverLog", sanitizeLogLine(line))
		}
	}()

	go func() {
		cmd.Wait()
		serverMgr.mu.Lock()
		serverMgr.status.Running = false
		serverMgr.status.Ready = false
		serverMgr.status.PID = 0
		serverMgr.mu.Unlock()
		runtime.EventsEmit(a.ctx, "serverStatus", serverMgr.status)
	}()

	return nil
}

// WaitForServerReady 等待服务器启动完毕
func (a *App) WaitForServerReady() error {
	serverMgr.mu.Lock()
	readyCh := serverMgr.readyCh
	if serverMgr.status.Ready {
		serverMgr.mu.Unlock()
		return nil
	}
	serverMgr.mu.Unlock()
	if readyCh == nil {
		return fmt.Errorf("服务器未在运行")
	}
	select {
	case <-readyCh:
		return nil
	case <-time.After(180 * time.Second):
		return fmt.Errorf("服务器启动超时（3分钟）")
	}
}
