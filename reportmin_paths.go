package main

import (
	"strings"
)

func lastPathSegment(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	seg := p
	if idx >= 0 && idx+1 < len(p) {
		seg = p[idx+1:]
	}
	if len(seg) > 40 {
		seg = seg[:40]
	}
	return seg
}

// MinimizeMap 对扁平字段表做白名单 + 长度 + 预算最小化；返回保留字段数与丢弃数。
func MinimizeMap(in map[string]string) (map[string]string, int) {
	pol := defaultReportPolicy()
	out := make(map[string]string, len(in))
	var dropped int
	for k, v := range in {
		if !pol.AllowField(k) {
			dropped++
			continue
		}
		v = ScrubTelemetryValue(v)
		if len(v) > pol.MaxFieldLen {
			v = v[:pol.MaxFieldLen-3] + "..."
		}
		out[k] = v
	}
	return out, dropped
}
