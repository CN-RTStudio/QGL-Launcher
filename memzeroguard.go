package main

import (
	"strings"
)

const (
	MZGReasonBufferNotZeroized   = "mem-sensitive-buffer-not-zeroized"
	MZGReasonZeroizedTooLate     = "mem-buffer-zeroized-after-retention"
	MZGReasonImmutableStringCopy = "mem-credential-converted-to-immutable-string"
	MZGReasonTokenInLongLived    = "mem-token-retained-in-long-lived-object"
	MZGReasonTokenInURL          = "mem-token-embedded-in-url"
	MZGReasonDoubleZeroize       = "mem-buffer-double-zeroize-signal"
	MZGReasonUnknownBuffer       = "mem-zeroize-unknown-buffer-id"
)

type MZGBuffer struct {
	ID            string
	Label         string // password/refresh-token/client-secret
	Length        int
	Zeroized      bool
	Retention     bool // 清零后/未清零是否仍被长生命周期对象引用
	ImmutableCopy bool // 是否被转成不可变 string
}
type MZGFinding struct {
	Reason string
	Detail string
}
type MemZeroTracker struct {
	buffers map[string]*MZGBuffer
	order   []string
}

func NewMemZeroTracker() *MemZeroTracker {
	return &MemZeroTracker{buffers: map[string]*MZGBuffer{}}
}

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
