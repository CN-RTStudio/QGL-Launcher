package main

// lockfileguard.go —— 实例/配置写操作的文件锁获取-释放配对与陈旧锁守卫（纯状态建模）。
//
// 背景：
//   启动器对实例目录、存档、配置的并发写需要互斥。锁管理常见缺陷：
//     - 获取后在错误分支漏释放（资源泄漏，后续实例永久无法启动写操作）；
//     - 重复释放 / 释放未持有的锁（破坏他人锁，导致互斥失效）；
//     - 陈旧锁：持锁进程崩溃，锁记录仍在且带未来时间戳，没有 owner 心跳判定；
//     - 同资源可被两个 token 同时持有（互斥被绕过）。
//   本模块在内存里建模锁表，校验 acquire/release 序列与 TTL，不触碰真实文件系统，不用正则。

import "sync"

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

// Release 释放资源锁，仅持有者可释放。
func (m *LFManager) Release(resource, token string) (ok bool, findings []LFFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.records[resource]
	if !exists {
		return false, []LFFinding{{Reason: LFReasonReleaseNotHeld, Resource: resource}}
	}
	if rec.OwnerToken != token {
		return false, []LFFinding{{Reason: LFReasonReleaseWrongOwner, Resource: resource}}
	}
	delete(m.records, resource)
	return true, nil
}

// Heartbeat 续租；非持有者或未来时间戳拒绝。
func (m *LFManager) Heartbeat(resource, token string, tick uint64) (ok bool, findings []LFFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.records[resource]
	if !exists || rec.OwnerToken != token {
		return false, []LFFinding{{Reason: LFReasonReleaseNotHeld, Resource: resource}}
	}
	if tick < rec.LastHeartbeat {
		return false, []LFFinding{{Reason: LFReasonFutureTimestamp, Resource: resource}}
	}
	rec.LastHeartbeat = tick
	m.records[resource] = rec
	return true, nil
}

// Held 报告某资源当前是否被有效持有。
func (m *LFManager) Held(resource string, tick uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, exists := m.records[resource]
	return exists && !lfIsStale(rec, tick)
}

func lfIsStale(rec LFRecord, tick uint64) bool {
	if rec.TTL == 0 {
		return false
	}
	return tick > rec.LastHeartbeat+rec.TTL
}

// LFHasReason 判定结果含某类问题。
func LFHasReason(findings []LFFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
