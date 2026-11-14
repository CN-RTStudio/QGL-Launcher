package main

import (
	"archive/zip"
	"io"
	"strings"
)

func (r *JarScanReport) addRuleOnce(sev JarFindingSeverity, rule, entry, detail string) {
	if r.ruleSeen[rule] {
		return
	}
	r.ruleSeen[rule] = true
	r.add(sev, rule, entry, detail)
}
func scanClassBehavior(rep *JarScanReport, f *zip.File, entryName string, spent int) int {
	rc, err := f.Open()
	if err != nil {
		return 0
	}
	defer rc.Close()

	capLeft := jarScanClassBytesCap - spent
	if capLeft <= 0 {
		return 0
	}
	limit := int64(jarScanPerClassCap)
	if int64(capLeft) < limit {
		limit = int64(capLeft)
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil || len(data) == 0 {
		return 0
	}

	texts := classConstantPoolUTF8(data)
	if texts == nil {
		// 不是可识别的 class 结构（可能被截断），不计入已扫描配额之外的噪音。
		return 0
	}
	var blob strings.Builder
	blob.Grow(len(data))
	for _, s := range texts {
		blob.WriteString(s)
		blob.WriteByte('\n')
	}
	joined := blob.String()
	lowerJoined := strings.ToLower(joined)
	for _, p := range jarBehaviorPatterns {
		needle := strings.ToLower(p.require)
		if !strings.Contains(lowerJoined, needle) {
			continue
		}
		if p.andAlso != "" && !strings.Contains(lowerJoined, strings.ToLower(p.andAlso)) {
			continue
		}
		rep.addRuleOnce(p.sev, p.rule, entryName, p.detail)
	}
	return len(data)
}

type classReader struct {
	b   []byte
	off int
	ok  bool
}
