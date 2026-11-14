package main

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

var defaultSecurityAudit = newSecurityAudit()

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
