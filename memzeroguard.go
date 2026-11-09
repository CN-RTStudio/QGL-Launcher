package main

// memzeroguard.go —— 敏感字节缓冲清零与令牌内存留存守卫。
//
// 背景：
//   Go 的 string 不可变、密码/令牌常以明文驻留在堆上，且 GC 前内存可能被转储（heapdump/
//   crash dump/休眠文件/交换分区）读到。虽然无法像 C 那样可靠擦除 string，但工程上仍应：
//     - 口令类用可变 []byte 接收，并在用完显式清零（Zeroize），而不是随手转 string 长期持有；
//     - access/refresh token 不复制进全局/单例/长生命周期结构，不拼进 URL 与日志；
//     - 凭据结构体用完要有 Close/Zeroize，且只被最小作用域引用；
//     - 避免 string([]byte(password)) 这种产生不可擦副本的转换（至少登记并尽快丢弃）。
//   本模块是一个"显式登记 + 复核"小内核：调用方在接触敏感数据时登记缓冲，在释放点核对是否已
//   清零，并对令牌留存视图做判定。纯内存/字符串判定，不使用正则，也不声称能对抗运行时插桩。

import "strings"

const (
	MZGReasonBufferNotZeroized   = "mem-sensitive-buffer-not-zeroized"
	MZGReasonZeroizedTooLate     = "mem-buffer-zeroized-after-retention"
	MZGReasonImmutableStringCopy = "mem-credential-converted-to-immutable-string"
	MZGReasonTokenInLongLived    = "mem-token-retained-in-long-lived-object"
	MZGReasonTokenInURL          = "mem-token-embedded-in-url"
	MZGReasonDoubleZeroize       = "mem-buffer-double-zeroize-signal"
	MZGReasonUnknownBuffer       = "mem-zeroize-unknown-buffer-id"
)

// MZGBuffer 是登记的一个敏感缓冲快照。
type MZGBuffer struct {
	ID            string
	Label         string // password/refresh-token/client-secret
	Length        int
	Zeroized      bool
	Retention     bool // 清零后/未清零是否仍被长生命周期对象引用
	ImmutableCopy bool // 是否被转成不可变 string
}

// MZGFinding 记录一处内存处理风险。
type MZGFinding struct {
	Reason string
	Detail string
}

// MemZeroTracker 登记敏感缓冲并在释放点复核。
type MemZeroTracker struct {
	buffers map[string]*MZGBuffer
	order   []string
}

// NewMemZeroTracker 创建跟踪器。
func NewMemZeroTracker() *MemZeroTracker {
	return &MemZeroTracker{buffers: map[string]*MZGBuffer{}}
}

// Register 登记一个敏感缓冲。
func (t *MemZeroTracker) Register(id, label string, length int) {
	if _, exists := t.buffers[id]; exists {
		return
	}
	t.buffers[id] = &MZGBuffer{ID: id, Label: label, Length: length}
	t.order = append(t.order, id)
}

// MarkImmutableCopy 记录该敏感值被转成了不可擦 string。
func (t *MemZeroTracker) MarkImmutableCopy(id string) {
	if b := t.buffers[id]; b != nil {
		b.ImmutableCopy = true
	}
}

// MarkRetention 记录该值被长生命周期对象/全局引用。
func (t *MemZeroTracker) MarkRetention(id string) {
	if b := t.buffers[id]; b != nil {
		b.Retention = true
	}
}

// ZeroizeBuffer 标记缓冲已清零。重复清零返回 false（提示调用方生命周期可能混乱）。
func (t *MemZeroTracker) ZeroizeBuffer(id string) bool {
	b := t.buffers[id]
	if b == nil {
		return false
	}
	if b.Zeroized {
		return false
	}
	b.Zeroized = true
	return true
}

// ZeroizeBytes 真正擦除一段字节（供调用方在释放前使用）。
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Audit 复核所有已登记缓冲的处置。
func (t *MemZeroTracker) Audit() (safe bool, findings []MZGFinding) {
	for _, id := range t.order {
		b := t.buffers[id]
		if b == nil {
			continue
		}
		if !b.Zeroized {
			findings = append(findings, MZGFinding{Reason: MZGReasonBufferNotZeroized, Detail: b.Label})
		}
		if b.Zeroized && b.Retention {
			findings = append(findings, MZGFinding{Reason: MZGReasonZeroizedTooLate, Detail: b.Label})
		}
		if b.ImmutableCopy {
			findings = append(findings, MZGFinding{Reason: MZGReasonImmutableStringCopy, Detail: b.Label})
		}
		if b.Retention && !b.Zeroized {
			findings = append(findings, MZGFinding{Reason: MZGReasonTokenInLongLived, Detail: b.Label})
		}
	}
	return len(findings) == 0, findings
}

// MZGInspectTokenUsage 检查令牌的使用形态：是否被拼进 URL/query。
func MZGInspectTokenUsage(tokenRef string, urlOrQuery string) (safe bool, findings []MZGFinding) {
	if tokenRef == "" || urlOrQuery == "" {
		return true, nil
	}
	if strings.Contains(urlOrQuery, tokenRef) {
		findings = append(findings, MZGFinding{Reason: MZGReasonTokenInURL})
	}
	return len(findings) == 0, findings
}
