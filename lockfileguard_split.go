package main

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
