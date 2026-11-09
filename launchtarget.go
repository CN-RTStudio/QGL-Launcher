package main

const (
	// 这些上限按“宁大勿误杀”取值：正常启动参数远到不了，只在明显异常 / 疑似
	// 恶意构造时触发，绝不把正常游戏启动挡在门外。
	maxLaunchArgs         = 1024
	maxLaunchArgBytes     = 32 * 1024
	maxClasspathEntries   = 8192
	maxMainClassLen       = 1024
	maxPathLen            = 4096
	maxMemoryMBUpperBound = 1 << 20 // 1 TiB（1048576 MB）级 sanity，非功能性小上限
	minMemoryMBLowerBound = 8
)
const (
	launchSeverityCritical = "critical"
	launchSeverityWarn     = "warn"
	launchSeverityInfo     = "info"
)

type LaunchFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Field    string `json:"field"`
	Detail   string `json:"detail"`
}
type LaunchPlan struct {
	JavaExe      string   // java 可执行（绝对路径）
	WorkDir      string   // cmd.Dir 工作目录
	JarRelPath   string   // -jar 目标，必须是相对 WorkDir 的 .jar（与 MainClass 二选一）
	Classpath    []string // -classpath 各条目，相对 WorkDir
	MainClass    string   // 主类（无 -jar 时）
	ProgramArgs  []string // 主类之后传给游戏 / 服务器的参数
	MinMemoryMB  int      // -Xms
	MaxMemoryMB  int      // -Xmx
	AllowedRoots []string // WorkDir/jar/classpath 允许落在的根目录集合
}
type LaunchAudit struct {
	Findings []LaunchFinding `json:"findings"`
	Critical int             `json:"critical"`
	Warns    int             `json:"warns"`
}
