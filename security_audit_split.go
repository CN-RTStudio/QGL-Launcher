package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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
