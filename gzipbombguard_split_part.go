package main

func (m *GZBMonitor) abort(reason, detail string) {
	m.aborted = true
	m.abortReason = reason
}

// AbortReason 返回中止原因。
func (m *GZBMonitor) AbortReason() string { return m.abortReason }

// Produced 返回当前累计解压产出。
func (m *GZBMonitor) Produced() int64 { return m.producedOut }

func trimSpaceGZB(s string) string {
	start, end := 0, len(s)
	for start < end && isSpaceGZB(s[start]) {
		start++
	}
	for end > start && isSpaceGZB(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpaceGZB(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func splitCommaGZB(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func itoaGZB(i int) string {
	return itoaGZB64(int64(i))
}

func itoaGZB64(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
