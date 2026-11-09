package main

import (
	"strings"
)

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
