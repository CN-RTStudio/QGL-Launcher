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

// scanClassBehavior 读取单个 class（有字节上限），只解析常量池里的 UTF8 项做能力
// 特征匹配，绝不加载 / 验证 / 执行字节码。返回实际读取的字节数（用于全局预算）；
// class 损坏或被截断时返回 0，跳过而不影响其他条目。
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

// classReader 是带边界检查的 class 文件只读游标，越界后 ok=false 并短路。
type classReader struct {
	b   []byte
	off int
	ok  bool
}

func (r *classReader) u1() int {
	if !r.ok || r.off+1 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])
	r.off++
	return v
}

func (r *classReader) u2() int {
	if !r.ok || r.off+2 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<8 | int(r.b[r.off+1])
	r.off += 2
	return v
}

func (r *classReader) u4() int {
	if !r.ok || r.off+4 > len(r.b) {
		r.ok = false
		return 0
	}
	v := int(r.b[r.off])<<24 | int(r.b[r.off+1])<<16 | int(r.b[r.off+2])<<8 | int(r.b[r.off+3])
	r.off += 4
	return v
}

func (r *classReader) take(n int) []byte {
	if !r.ok || n < 0 || r.off+n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}
