package main

const (
	// log4jMaxEntries 限制参与扫描的条目数，防海量条目耗尽 CPU。
	log4jMaxEntries = 50000
	// log4jTextCap 限制单个配置 / 文本条目最多读取字节数。
	log4jTextCap = 1 << 20 // 1 MiB
	// log4jMaxClasses 限制参与常量池分析的 class 条数。
	log4jMaxClasses = 3000
	// log4jClassCap 限制单个 class 读取字节数。
	log4jClassCap = 1 << 20 // 1 MiB
	// log4jClassBytesCap 限制所有 class 累计读取字节数。
	log4jClassBytesCap = 16 << 20 // 16 MiB
	// log4jNestedDepth 是嵌套 jar 递归扫描的最大深度（外层记为第 1 层）。
	log4jNestedDepth = 2
	// log4jMaxNested 限制参与递归的嵌套 jar 数量。
	log4jMaxNested = 32
	// log4jNestedBytesCap 限制嵌套 jar 累计读取字节数。
	log4jNestedBytesCap = 64 << 20 // 64 MiB
	// log4jPerNestedCap 限制单个嵌套 jar 读取字节数。
	log4jPerNestedCap = 8 << 20 // 8 MiB
)

type Log4ShellReport struct {
	Entries      int          `json:"entries"`
	ConfigFiles  int          `json:"configFiles"`
	Findings     []JarFinding `json:"findings"`
	findingSeen  map[string]bool
	limitEntries bool
	limitNested  bool
}

func (r *Log4ShellReport) Blocked() bool {
	if r == nil {
		return false
	}
	for _, f := range r.Findings {
		if f.Severity == JarSeverityCritical {
			return true
		}
	}
	return false
}
