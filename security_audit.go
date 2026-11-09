package main

// security_audit.go 提供启动器自己的"安全事件审计日志"。
//
// 为什么需要它：启动器里已经有很多道安全闸——Zip Slip / 解压炸弹预检、
// 外部链接白名单、JVM 注入环境变量剥离、Java 安装包校验、凭证文件拒符号
// 链接写穿等。但这些拦截以前只有两种归宿：要么变成一个 error 返回给调用方
// （用户只看到"失败了"），要么只进游戏启动日志（混在成千上万行 MC 输出里，
// 还会被轮转覆盖）。被拦下的攻击尝试本身没有任何独立留痕：
//
//   - 用户无法区分"网络抖动导致的下载失败"和"压缩包里真的藏着越界路径"；
//   - 反复被触发的拦截（同一个恶意整合包被解压了十几次）没有聚合视图；
//   - 事后排查机器上是否有人动过 TEMP / 凭证文件，没有线索。
//
// 本模块把这些事件单独写到 userData 下的 security-audit.jsonl（JSON Lines，
// 一行一个事件，便于 grep / 转发给排查工具），同时在内存里保留一个定长环形
// 缓冲，Wails 前端可通过 GetSecurityEvents 直接查看最近的安全事件。
//
// 安全要求：
//   - detail 必须脱敏（复用 sanitizeLogLine）并限长，令牌 / 内网 IP 不落盘；
//   - 同一事件 5 分钟内重复触发做聚合计数，避免恶意内容用海量事件刷爆磁盘；
//   - 文件 0600、目录 0700；超过 1MiB 轮转，最多保留 2 份历史归档；
//   - 审计写入失败绝不影响主流程（安全功能不能因为日志写不了而拒绝启动游戏）。

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// 审计事件类别：新增拦截点时优先复用已有类别，确实是新面再新增常量。
	auditCategoryZip          = "zip-entry"      // 压缩包条目：Zip Slip / 特殊条目 / 炸弹
	auditCategoryJarScan      = "jar-scan"       // Mod jar 静态内容扫描：JVM 代理/根可执行/coremod 脚本
	auditCategoryLog4Shell    = "log4shell"      // Log4Shell/JNDI 静态扫描：JndiLookup 类 / ${jndi:} / 外联命名
	auditCategoryExternalURL  = "external-url"   // 外部链接白名单拦截
	auditCategoryJVMEnv       = "jvm-env"        // 游戏 JVM 隐式参数环境变量剥离
	auditCategoryLaunch       = "launch-audit"   // 游戏/服务器启动目标、命令行与 classpath 归属审计
	auditCategoryInstaller    = "java-installer" // Java 安装包落地 / 执行校验
	auditCategoryPrivateWrite = "private-write"  // 凭证 / 配置文件写入防护
	auditCategoryHashVerify   = "hash-verify"    // 下载文件哈希校验失败
	auditCategoryRateLimit    = "rate-limit"     // 请求限流触发
	auditCategoryPermission   = "permission"     // 前端 / 设备权限拒绝
	auditCategoryConsole      = "server-console" // 服务端控制台 stdin 命令净化 / 灌入限流
	auditCategoryConfig       = "config-input"   // 写进用户配置的外部输入（主题色 / 版本 ID）白名单收口
	auditCategoryReclaim      = "reclaim"        // 下载残留临时文件 / 孤儿侧车的安全回收

	auditSeverityInfo     = "info"
	auditSeverityWarn     = "warn"
	auditSeverityCritical = "critical"

	auditActionBlocked  = "blocked"  // 恶意 / 违规内容被拦下
	auditActionStripped = "stripped" // 危险成分被移除后流程继续
	auditActionRejected = "rejected" // 请求被拒绝（权限 / 白名单）
	auditActionRepeated = "repeated" // 前一条事件在窗口内重复出现的聚合记录
	auditActionDetected = "detected" // 静态扫描发现风险但未阻断（warn/info 记录）
	auditActionReset    = "reset"    // 台账 / 状态被显式清空
	auditActionFailed   = "failed"   // 内部写盘 / 落盘等基础设施失败（非业务拒绝）

	auditRingCap          = 1000               // 内存环形缓冲容量（条）
	auditMaxFileBytes     = int64(1024 * 1024) // 单文件 1 MiB
	auditMaxDetailRunes   = 500                // 单条 detail 最大字符数
	auditDedupWindow      = 5 * time.Minute    // 同键事件聚合窗口
	auditLogFileName      = "security-audit.jsonl"
	auditLogArchiveSuffix = ".1"
)

// SecurityEvent 是一条安全事件的对外结构（也用于 JSONL 落盘）。
// 字段全部使用内置类型，避免 Wails 绑定 / encoding/json 上的自定义序列化。
type SecurityEvent struct {
	OccurredAt time.Time `json:"time"`
	EpochMS    int64     `json:"epoch_ms"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Action     string    `json:"action"`
	Source     string    `json:"source"`
	Detail     string    `json:"detail"`
	Count      int       `json:"count"`
}

// securityAudit 是审计器。进程内只需要一个实例（defaultSecurityAudit），
// 但写成结构体是为了单元测试可以独立构造、不碰真实文件系统。
type securityAudit struct {
	mu          sync.Mutex
	dir         string
	initialized bool
	filePath    string
	fileSize    int64
	ring        []SecurityEvent // 新事件放末尾，超容从头丢弃
	lastKey     string
	last        *SecurityEvent
	suppressed  int64
	now         func() time.Time // 测试可替换时钟
}

func newSecurityAudit() *securityAudit {
	return &securityAudit{
		ring: make([]SecurityEvent, 0, auditRingCap),
		now:  time.Now,
	}
}

// defaultSecurityAudit 是各安全拦截点直接调用的进程级实例。
// 初始化（initSecurityAudit）之前发生的事件只进内存环形缓冲，不丢；
// init 之后的事件同步追加到磁盘文件。
var defaultSecurityAudit = newSecurityAudit()

// initSecurityAudit 指定审计目录（通常是 .minecraft / QGL 数据目录），
// 创建 0700 目录并记录现有日志文件大小用于轮转判断。重复调用幂等。
func (s *securityAudit) initSecurityAudit(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initialized && s.dir == dir {
		return nil
	}
	if strings.TrimSpace(dir) == "" {
		return errAuditEmptyDir()
	}
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	s.dir = dir
	s.filePath = filepath.Join(dir, auditLogFileName)
	// 审计文件路径若已存在，必须是普通文件：预置的符号链接 / 目录 / 设备都意味着
	// 有人想借审计追加把事件内容写穿到别的文件，初始化阶段直接拒绝并保持未启用。
	if err := rejectNonRegular(s.filePath); err != nil {
		return err
	}
	s.fileSize = 0
	if info, err := os.Stat(s.filePath); err == nil && !info.IsDir() {
		s.fileSize = info.Size()
	}
	s.initialized = true
	return nil
}

func errAuditEmptyDir() error { return &auditError{msg: "审计目录为空"} }

type auditError struct{ msg string }

func (e *auditError) Error() string { return e.msg }

// sanitizeAuditDetail 对事件明细脱敏并限长：
// 先复用日志脱敏（access token / 邮箱 / UUID / 内网 IP），再去掉控制字符。
