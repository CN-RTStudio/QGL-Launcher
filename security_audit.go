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
	"encoding/json"
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
func sanitizeAuditDetail(detail string) string {
	s := sanitizeLogLine(detail)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	runes := []rune(s)
	if len(runes) > auditMaxDetailRunes {
		s = string(runes[:auditMaxDetailRunes]) + "…"
	}
	return s
}

func validAuditCategory(c string) bool {
	switch c {
	case auditCategoryZip, auditCategoryExternalURL, auditCategoryJVMEnv,
		auditCategoryInstaller, auditCategoryPrivateWrite, auditCategoryHashVerify,
		auditCategoryRateLimit, auditCategoryPermission, auditCategoryJarScan,
		auditCategoryLog4Shell, auditCategoryConsole, auditCategoryConfig,
		auditCategoryReclaim:
		return true
	}
	return false
}

func validAuditSeverity(v string) bool {
	return v == auditSeverityInfo || v == auditSeverityWarn || v == auditSeverityCritical
}

func validAuditAction(a string) bool {
	return a == auditActionBlocked || a == auditActionRejected ||
		a == auditActionStripped || a == auditActionRepeated || a == auditActionDetected
}

func auditDedupKey(category, action, source, detail string) string {
	// detail 只取前 96 个字符参与去重：路径前缀 / 主机名相同就算同一类事件，
	// 末尾变化的字节数 / 条目名不影响聚合判定。
	key := category + "\x00" + action + "\x00" + source + "\x00"
	runes := []rune(detail)
	if len(runes) > 96 {
		key += string(runes[:96])
	} else {
		key += detail
	}
	return key
}

// pushRing 以"新事件在末尾、超容从头丢弃"的方式维护定长环形缓冲。
func (s *securityAudit) pushRing(e SecurityEvent) {
	if len(s.ring) >= auditRingCap {
		copy(s.ring, s.ring[1:])
		s.ring[len(s.ring)-1] = e
		return
	}
	s.ring = append(s.ring, e)
}

// appendLineLocked 把一条事件以 JSONL 形式追加到文件，并在超限时轮转。
// 调用方必须持有 s.mu。任何 IO 错误都直接返回，由上层吞掉（审计不阻塞主流程）。
func (s *securityAudit) appendLineLocked(e SecurityEvent) error {
	if !s.initialized {
		return nil
	}
	if s.fileSize >= auditMaxFileBytes {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// 每次追加前再做一次非普通文件检查：init 之后若有人把审计路径换成符号链接，
	// 这里在 O_APPEND（会跟随链接）之前拦下，防止写穿到链接目标。
	if err := rejectNonRegular(s.filePath); err != nil {
		return err
	}
	f, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, privateFilePerm)
	if err != nil {
		return err
	}
	n, err := f.Write(line)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.fileSize += int64(n)
	return nil
}

// rotateLocked 把当前日志改名归档，新事件从空文件重新开始写。
// 只保留一份 .1 归档：再次轮转时旧 .1 直接删除，避免无限堆积。
func (s *securityAudit) rotateLocked() error {
	archive := s.filePath + auditLogArchiveSuffix
	if _, err := os.Lstat(s.filePath); err != nil {
		if os.IsNotExist(err) {
			s.fileSize = 0
			return nil
		}
		return err
	}
	// 归档目标若已存在（含被人预埋的符号链接），先删链接本身再改名。
	if _, err := os.Lstat(archive); err == nil {
		if rmErr := os.Remove(archive); rmErr != nil {
			return rmErr
		}
	}
	if err := os.Rename(s.filePath, archive); err != nil {
		return err
	}
	s.fileSize = 0
	return nil
}

// flushSuppressedLocked 把上一条事件在聚合窗口内被压下的重复次数补一条
// "repeated" 汇总记录，保证磁盘日志里既能看到首次事件，也能看到它后来又
// 触发了多少次，而不会每次都写一行。
func (s *securityAudit) flushSuppressedLocked(now time.Time) {
	if s.last == nil || s.suppressed == 0 {
		return
	}
	summary := SecurityEvent{
		OccurredAt: now,
		EpochMS:    now.UnixMilli(),
		Category:   s.last.Category,
		Severity:   s.last.Severity,
		Action:     auditActionRepeated,
		Source:     s.last.Source,
		Detail:     sanitizeAuditDetail(s.last.Detail),
		Count:      int(s.suppressed),
	}
	_ = s.appendLineLocked(summary)
	s.suppressed = 0
}

// record 是审计器核心：校验、脱敏、去重聚合、入内存环、落盘。
// 任何非法输入 / IO 失败都不会 panic 或返回影响调用方的错误。
func (s *securityAudit) record(category, severity, action, source, detail string) {
	if !validAuditCategory(category) || !validAuditSeverity(severity) || !validAuditAction(action) {
		return
	}
	source = sanitizeAuditDetail(source)
	detail = sanitizeAuditDetail(detail)
	if source == "" {
		source = "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := auditDedupKey(category, action, source, detail)
	if s.last != nil && s.lastKey == key && now.Sub(s.last.OccurredAt) < auditDedupWindow {
		s.last.Count++
		s.last.OccurredAt = now
		s.suppressed++
		return
	}

	// 新类别事件到来：先把上一条的重复汇总落盘。
	s.flushSuppressedLocked(now)

	e := SecurityEvent{
		OccurredAt: now,
		EpochMS:    now.UnixMilli(),
		Category:   category,
		Severity:   severity,
		Action:     action,
		Source:     source,
		Detail:     detail,
		Count:      1,
	}
	s.pushRing(e)
	_ = s.appendLineLocked(e)
	s.lastKey = key
	copied := e
	s.last = &copied
}

// snapshot 返回内存环中事件的副本（按时间倒序：最新在前）。
// category 非空时只返回该类别。limit<=0 或超过环容量按环容量处理。
func (s *securityAudit) snapshot(category string, limit int) []SecurityEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.ring) {
		limit = len(s.ring)
	}
	out := make([]SecurityEvent, 0, limit)
	for i := len(s.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.ring[i]
		if category != "" && e.Category != category {
			continue
		}
		out = append(out, e)
	}
	return out
}

// clear 清空内存环与磁盘日志（含归档）。供前端"清空安全事件"调用。
func (s *securityAudit) clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring = s.ring[:0]
	s.last = nil
	s.lastKey = ""
	s.suppressed = 0
	if !s.initialized {
		return nil
	}
	for _, p := range []string{s.filePath, s.filePath + auditLogArchiveSuffix} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	s.fileSize = 0
	return nil
}

// ===== 包级便捷函数：拦截点只调这些，不必关心实例 =====

// recordSecurityEvent 记录一条安全事件。
// detail 在落盘前统一过 reportmin 的值级去敏（剥本机绝对路径 / 令牌 / 长十六
// 进制 / 换行折叠），防止安全事件文件把本机结构或凭据泄给排查者与未来遥测通道。
func recordSecurityEvent(category, severity, action, source, detail string) {
	detail = ScrubTelemetryValue(detail)
	defaultSecurityAudit.record(category, severity, action, source, detail)
}

// snapshotSecurityEvents 供主进程 / 测试读取最近事件。
func snapshotSecurityEvents(category string, limit int) []SecurityEvent {
	return defaultSecurityAudit.snapshot(category, limit)
}

// clearSecurityEvents 清空内存与磁盘上的全部安全事件。
func clearSecurityEvents() error { return defaultSecurityAudit.clear() }

// ===== 暴露给 Wails 前端的方法（App 绑定方法）=====

// GetSecurityEvents 返回最近的安全事件，最新在前。
//
//	limit    ：条数，非法或超出范围时回落到默认 100，硬上限 1000；
//	category ：可选类别过滤，传非白名单类别时直接返回错误而不是悄悄返回空。
func (a *App) GetSecurityEvents(limit int, category string) ([]SecurityEvent, error) {
	if category != "" && !validAuditCategory(category) {
		return nil, &auditError{msg: "未知的安全事件类别"}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > auditRingCap {
		limit = auditRingCap
	}
	return snapshotSecurityEvents(category, limit), nil
}

// ClearSecurityEvents 清空安全事件（内存环 + JSONL + 归档）。
func (a *App) ClearSecurityEvents() error {
	return clearSecurityEvents()
}
