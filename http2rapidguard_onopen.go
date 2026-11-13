package main

func (m *H2Monitor) OnOpen(streamID int) (allowed bool, findings []H2Finding) {
	if m.blocked {
		return false, []H2Finding{{Reason: m.blockedReason}}
	}
	if m.active[streamID] {
		// 重复打开同 ID 属于协议异常
		return false, []H2Finding{{Reason: H2ReasonWindowExhausted,
			Detail: "duplicate-stream-" + itoaH2(streamID)}}
	}
	if len(m.active) >= m.policy.MaxConcurrentStreams {
		m.block(H2ReasonConcurrentStream, itoaH2(len(m.active)))
		return false, []H2Finding{{Reason: H2ReasonConcurrentStream,
			Detail: itoaH2(len(m.active))}}
	}
	m.active[streamID] = true
	m.opened++
	return true, nil
}

func (m *H2Monitor) OnReset(streamID int) (allowed bool, findings []H2Finding) {
	if !m.active[streamID] {
		// 取消一个我们没有的活跃流：可疑的伪造/重放
		return false, []H2Finding{{Reason: H2ReasonUnknownStream,
			Detail: itoaH2(streamID)}}
	}
	delete(m.active, streamID)
	m.reset++

	idx := m.tick % len(m.resetWindow)
	m.resetWindow[idx]++

	if m.windowReset() > m.policy.MaxResetPerWindow {
		m.block(H2ReasonResetBurst, itoaH2(m.windowReset()))
		return false, []H2Finding{{Reason: H2ReasonResetBurst}}
	}

	if m.opened > 0 {
		ratio := m.reset * 100 / m.opened
		if ratio > m.policy.ResetRatioPercent && m.opened >= 10 {
			m.block(H2ReasonResetRatio, itoaH2(ratio))
			return false, []H2Finding{{Reason: H2ReasonResetRatio,
				Detail: itoaH2(ratio)}}
		}
	}
	return true, nil
}
func (m *H2Monitor) OnGOAWAY() {
	m.goawaySeen = true
}

func (m *H2Monitor) OnReconnect() (allowed bool, findings []H2Finding) {
	if !m.goawaySeen {
		return true, nil
	}
	m.reconnectsWindow++
	if m.reconnectsWindow > m.policy.MaxGOAWAYReconnects {
		m.block(H2ReasonGOAWAYReconnect, itoaH2(m.reconnectsWindow))
		return false, []H2Finding{{Reason: H2ReasonGOAWAYReconnect,
			Detail: itoaH2(m.reconnectsWindow)}}
	}
	return true, nil
}

func (m *H2Monitor) windowReset() int {
	sum := 0
	for _, n := range m.resetWindow {
		sum += n
	}
	return sum
}
