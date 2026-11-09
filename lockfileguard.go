package main

import (
	"sync"
)

const (
	LFReasonDoubleAcquire     = "lockfile-already-held-by-another-token"
	LFReasonReleaseNotHeld    = "lockfile-release-without-acquire"
	LFReasonReleaseWrongOwner = "lockfile-release-by-non-owner-token"
	LFReasonStaleLock         = "lockfile-stale-owner-without-fresh-heartbeat"
	LFReasonFutureTimestamp   = "lockfile-heartbeat-in-the-future"
	LFReasonReacquireLeak     = "lockfile-reacquire-without-prior-release"
)

// LFFinding 记录一处锁错误。
type LFFinding struct {
	Reason   string
	Resource string
}

// LFRecord 是一把锁的状态。
type LFRecord struct {
	OwnerToken    string
	AcquiredTick  uint64
	LastHeartbeat uint64
	TTL           uint64
}

// LFManager 管理多资源锁表。
type LFManager struct {
	mu      sync.Mutex
	records map[string]LFRecord
}

// NewLFManager 创建锁管理器。
func NewLFManager() *LFManager {
	return &LFManager{records: map[string]LFRecord{}}
}

// Acquire 尝试获取资源锁。
func (m *LFManager) Acquire(resource, token string, tick, ttl uint64) (ok bool, findings []LFFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.records[resource]
	if exists {
		if rec.OwnerToken == token {
			return false, []LFFinding{{Reason: LFReasonReacquireLeak, Resource: resource}}
		}
		if lfIsStale(rec, tick) {
			// 陈旧锁可被接管
			findings = append(findings, LFFinding{Reason: LFReasonStaleLock, Resource: resource})
		} else {
			return false, []LFFinding{{Reason: LFReasonDoubleAcquire, Resource: resource}}
		}
	}

	m.records[resource] = LFRecord{
		OwnerToken: token, AcquiredTick: tick,
		LastHeartbeat: tick, TTL: ttl,
	}
	// 走到这里：要么原本无锁，要么接管的是陈旧锁（findings 里带 stale 警告），均允许持有。
	return true, findings
}
