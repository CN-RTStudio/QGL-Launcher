package main

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
